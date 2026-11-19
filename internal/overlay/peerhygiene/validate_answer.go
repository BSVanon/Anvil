package peerhygiene

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/BSVanon/Anvil/internal/scriptcost"
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
	_, _, err := PrepareLookupAnswer(contentType, body)
	return err
}

// PrepareLookupAnswer checks one peer's /lookup reply as ValidateLookupAnswer
// does and returns the reply to hand go-sdk's facilitator in its place, with
// its Content-Type. A JSON reply is handed on as it came. A binary reply is
// handed on as the JSON answer of the outputs decodeLookupAnswer rebuilt from
// it, so go-sdk decodes exactly the outputs checked here instead of
// rebuilding them itself. Rebuilt by go-sdk v1.7.7, each output would carry
// every proof in its transaction's BUMP, so an answer of n outputs mined in
// one block would grow as n squared (see splitProofs); and Transaction.BEEF
// combines same-block proofs in place, so what go-sdk built for one output
// would depend on the outputs it built before, which no check of the outputs
// one by one can follow.
//
// The JSON handed on holds each output's BEEF in base64, so it is at most
// 4/3 MaxAnswerBEEFBytes plus some 40 bytes per output: 3.1 MiB at the caps.
// Decoding it keeps the BEEFs, MaxAnswerBEEFBytes, and about 48 bytes per
// output.
func PrepareLookupAnswer(contentType string, body []byte) (outType string, out []byte, err error) {
	if int64(len(body)) > MaxLookupResponseBytes {
		return "", nil, fmt.Errorf("%w: body is over %d bytes", ErrLookupResponseTooLarge, MaxLookupResponseBytes)
	}
	answer, err := decodeLookupAnswer(contentType, body)
	if err != nil {
		return "", nil, err
	}
	for i, o := range answer.Outputs {
		if err := checkOutput(o); err != nil {
			return "", nil, fmt.Errorf("lookup: output %d of the answer: %w", i, err)
		}
	}
	if contentType != binaryContentType {
		return contentType, body, nil
	}
	return "application/json", encodeOutputList(answer.Outputs), nil
}

// encodeOutputList writes an output-list answer of outputs byte for byte as
// encoding/json writes the lookup.LookupAnswer, but into one buffer of exactly
// its size, where json.Marshal's growing buffer could hold twice that.
func encodeOutputList(outputs []*lookup.OutputListItem) []byte {
	const head, item, tail = `{"type":"output-list","outputs":[`, `{"beef":"","outputIndex":}`, `]}`
	if len(outputs) == 0 {
		return []byte(`{"type":"output-list"}`)
	}
	size := len(head) + len(tail) + len(outputs) - 1
	for _, o := range outputs {
		size += len(item) + base64.StdEncoding.EncodedLen(len(o.Beef)) + len(strconv.FormatUint(uint64(o.OutputIndex), 10))
	}
	b := make([]byte, 0, size)
	b = append(b, head...)
	for i, o := range outputs {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"beef":"`...)
		b = base64.StdEncoding.AppendEncode(b, o.Beef)
		b = append(b, `","outputIndex":`...)
		b = strconv.AppendUint(b, uint64(o.OutputIndex), 10)
		b = append(b, '}')
	}
	return append(b, tail...)
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

// checkOutputIndex requires index to name one of tx's outputs, and that
// output's locking script to decode to at most MaxOutputScriptChunks chunks.
// It compares as uint64 so the check holds on 32-bit platforms too, where
// upstream's own int(index) conversions could go negative.
func checkOutputIndex(tx *transaction.Transaction, index uint32) error {
	if uint64(index) >= uint64(len(tx.Outputs)) {
		return fmt.Errorf("output index %d is past the transaction's %d outputs", index, len(tx.Outputs))
	}
	if out := tx.Outputs[index]; out != nil && out.LockingScript != nil {
		if n := scriptcost.Chunks(*out.LockingScript, MaxOutputScriptChunks); n > MaxOutputScriptChunks {
			return fmt.Errorf("output %d's locking script decodes to over %d chunks", index, MaxOutputScriptChunks)
		}
	}
	return nil
}
