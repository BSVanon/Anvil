package peerhygiene

import (
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// parseBeef and newTransactionFromBEEF are the go-sdk parsers that go-sdk's
// lookup stack runs on every output of an answer. They are variables so a test
// can make them panic and check that checkOutput turns the panic into an
// error.
var (
	parseBeef              = transaction.ParseBeef
	newTransactionFromBEEF = transaction.NewTransactionFromBEEF
)

// ValidateLookupAnswer reports whether one peer's /lookup reply is safe to hand
// to go-sdk's stock lookup stack, which treats the reply as trusted. contentType
// is the reply's Content-Type header and body its complete body, which must be
// at most MaxLookupResponseBytes long. A nil error means that stack can decode
// and use the reply without panicking and without allocating past the bounds
// checked here, which are the per-answer caps in budget.go.
//
// The check is a superset of everything go-sdk v1.7.7 does with a reply, in
// the order it does it:
//
//  1. HTTPSOverlayLookupFacilitator.Lookup decodes the body with the same exact
//     Content-Type test that decodeLookupAnswer uses. decodeLookupAnswer runs
//     the same decoding, with every wire-supplied count, length and output
//     index checked against the bytes present before it is used, null outputs
//     rejected, and any panic recovered. It first prices the decoding: a
//     binary answer's shared BEEF by beefCost, a JSON answer by jsonCost, and
//     refuses one over MaxBEEFParseCost or MaxJSONDecodeCost before anything
//     parses it. It then caps the outputs at MaxLookupOutputs, counts every
//     output's BEEF (a binary output's re-serialization, repeats included)
//     against MaxAnswerBEEFBytes, and prices each JSON output's BEEF. Decoding
//     is deterministic, so a body that passes decodes upstream to the
//     identical LookupAnswer (the facilitator parity tests pin this), and
//     upstream's allocations stay within the same bounds: the outpoint list and
//     contexts within the body, the BEEF parse within its price, the output
//     BEEFs within MaxAnswerBEEFBytes and the JSON decode within its price.
//  2. LookupResolver.Query and FindCompetentHosts dereference every output,
//     call transaction.ParseBeef on its BEEF and TxID on the result.
//     FindCompetentHosts bounds-checks the output index itself.
//  3. topic.Broadcaster.FindInterestedHosts calls
//     transaction.NewTransactionFromBEEF on each output the resolver kept and
//     indexes tx.Outputs[OutputIndex] with neither a nil check nor a bounds
//     check.
//
// checkOutput runs steps 2 and 3 on every output, under recover. It rejects an
// output whose parsing panics, whose BEEF parses to no transaction where step
// 3 would dereference it, or whose index is past its transaction's outputs. An
// output whose BEEF fails to parse with an error is accepted, because upstream
// logs it and skips it. Every output's BEEF is priced within MaxBEEFParseCost
// (a binary output's is a subset of the priced shared BEEF), so each of these
// parses, here and upstream, stays within that bound too.
func ValidateLookupAnswer(contentType string, body []byte) error {
	if int64(len(body)) > MaxLookupResponseBytes {
		return fmt.Errorf("%w: body is over %d bytes", ErrLookupResponseTooLarge, MaxLookupResponseBytes)
	}
	answer, err := decodeLookupAnswer(contentType, body)
	if err != nil {
		return err
	}
	for i, out := range answer.Outputs {
		if err := checkOutput(out); err != nil {
			return fmt.Errorf("lookup: output %d of the answer: %w", i, err)
		}
	}
	return nil
}

// checkOutput repeats, under recover, what go-sdk's LookupResolver and topic
// Broadcaster do with one output of an answer.
func checkOutput(out *lookup.OutputListItem) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parsing its BEEF panicked: %v", r)
		}
	}()
	if out == nil {
		return errors.New("it is null")
	}
	// LookupResolver.Query and FindCompetentHosts.
	if _, tx, _, perr := parseBeef(out.Beef); perr == nil && tx != nil {
		_ = tx.TxID()
		if err := checkOutputIndex(tx, out.OutputIndex); err != nil {
			return err
		}
	}
	// topic.Broadcaster.FindInterestedHosts.
	tx, nerr := newTransactionFromBEEF(out.Beef)
	if nerr != nil {
		return nil
	}
	if tx == nil {
		return errors.New("its BEEF holds no transaction")
	}
	return checkOutputIndex(tx, out.OutputIndex)
}

// checkOutputIndex requires index to name one of tx's outputs. It compares as
// uint64 so the check holds on 32-bit platforms too, where upstream's own
// int(index) conversions could go negative.
func checkOutputIndex(tx *transaction.Transaction, index uint32) error {
	if uint64(index) >= uint64(len(tx.Outputs)) {
		return fmt.Errorf("output index %d is past the transaction's %d outputs", index, len(tx.Outputs))
	}
	return nil
}
