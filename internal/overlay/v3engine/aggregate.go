package v3engine

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/BSVanon/Anvil/internal/overlay/lookupguard"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// writeAggregatedAnswer serialises a LookupAnswer in the binary
// aggregation format required by vector overlay.lookup.3:
//
//	varint(numOutpoints) +
//	foreach[ txid(32 bytes, DISPLAY / big-endian order) + varint(outputIndex) +
//	         varint(contextLen) + context ] +
//	BEEF bytes (single BEEF holding every output's tx)
//
// Byte order: the canonical writer (OverlayExpress.ts) emits `tx.id()`
// (@bsv/sdk display order), and both canonical readers hex-encode the 32
// txid bytes and look the tx up in the BEEF by that hex — which is the
// display txid. So the txid MUST be written in display/big-endian order.
//
// Implementation cross-checked against ts-stack
// `overlay-express/src/OverlayExpress.ts:1205-1235`, the canonical
// reference. Differences:
//
//   - Go's `lookup.OutputListItem` has no Context field, so contextLen
//     is always 0 in this implementation. Documented divergence.
//   - The aggregated BEEF is built by parsing each output's per-tx
//     BEEF blob and merging into a single Beef via MergeBeef; the
//     final binary is written via Beef.Bytes().
//
// No stored output may fail the whole answer. The outputs' BEEFs come from
// storage, and go-sdk v1.7.7's MergeBump combines two proofs of one block
// (beef.go:828), which panics (merklepath.go:480) when the proof merged in
// declares more levels than the one already held, as two separately admitted
// BEEFs can. So an output without a BEEF, or whose
// BEEF cannot be parsed, is skipped and logged, and when merging any output's
// BEEF fails or panics, or the merged BEEF cannot be written, the answer is
// written by writePerOutputAnswer instead, every output with its own BEEF,
// with nothing merged.
//
// Responses with Type == AnswerTypeFreeform fail with a clear error
// because they have no outputs to aggregate; callers should not set
// x-aggregation:yes for freeform queries.
func writeAggregatedAnswer(w http.ResponseWriter, answer *lookup.LookupAnswer) error {
	if answer == nil {
		return errors.New("nil answer")
	}
	if answer.Type == lookup.AnswerTypeFreeform {
		return errors.New("x-aggregation incompatible with freeform answer (no outputs to aggregate)")
	}
	items := usableOutputs(answer.Outputs)
	payload, err := aggregateOutputs(items)
	if err != nil {
		slog.Warn("lookup: cannot aggregate the answer, answering with each output's own BEEF",
			"outputs", len(items), "error", err)
		return writePerOutputAnswer(w, items)
	}
	if int64(len(payload)) > routeguard.LookupAllowance {
		return fmt.Errorf("lookup response is over %d bytes", routeguard.LookupAllowance)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(payload)
	return err
}

// capAggregatedAnswer applies the response allowance to the bytes the binary
// writer will actually send. An output that cannot fit by itself is omitted;
// a later output that would overflow a non-empty page starts the next page.
func capAggregatedAnswer(result lookupguard.Result, cursor int) (lookupguard.Result, error) {
	answer := result.Answer
	if answer == nil || answer.Type == lookup.AnswerTypeFreeform {
		return result, nil
	}
	outputs := make([]*lookup.OutputListItem, 0, len(answer.Outputs))
	positions := make([]int, 0, len(answer.Outputs))
	omittedBefore := make([]int, 0, len(answer.Outputs))
	omitted := result.Omitted
	for i, item := range answer.Outputs {
		alone, err := aggregatedAnswerSize([]*lookup.OutputListItem{item})
		if err != nil {
			return lookupguard.Result{}, err
		}
		if alone > routeguard.LookupAllowance {
			omitted++
			continue
		}
		outputs = append(outputs, item)
		positions = append(positions, i)
		omittedBefore = append(omittedBefore, omitted)
	}

	size, err := aggregatedAnswerSize(outputs)
	if err != nil {
		return lookupguard.Result{}, err
	}
	if size > routeguard.LookupAllowance {
		first, last := 1, len(outputs)-1
		for first < last {
			middle := first + (last-first+1)/2
			middleSize, err := aggregatedAnswerSize(outputs[:middle])
			if err != nil {
				return lookupguard.Result{}, err
			}
			if middleSize <= routeguard.LookupAllowance {
				first = middle
			} else {
				last = middle - 1
			}
		}
		return lookupguard.Result{
			Answer:    outputListAnswer(outputs[:first]),
			Truncated: true,
			Next:      cursor + positions[first],
			Omitted:   omittedBefore[first],
		}, nil
	}
	if result.Truncated && len(outputs) > 0 {
		return lookupguard.Result{Answer: outputListAnswer(outputs), Truncated: true, Next: result.Next, Omitted: omitted}, nil
	}
	return lookupguard.Result{Answer: outputListAnswer(outputs), Omitted: omitted}, nil
}

func aggregatedAnswerSize(outputs []*lookup.OutputListItem) (int64, error) {
	items := usableOutputs(outputs)
	payload, err := buildAggregate(items)
	if err == nil {
		return int64(len(payload)), nil
	}
	return perOutputAnswerSize(items), nil
}

func outputListAnswer(outputs []*lookup.OutputListItem) *lookup.LookupAnswer {
	return &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: outputs}
}

// answerOutput is an output of a lookup answer with the txid of the
// transaction its BEEF carries.
type answerOutput struct {
	item *lookup.OutputListItem
	txid chainhash.Hash
}

// usableOutputs returns the outputs whose BEEF parses, with their txids, in
// the answer's order. It logs and skips every other output.
func usableOutputs(outputs []*lookup.OutputListItem) []answerOutput {
	usable := make([]answerOutput, 0, len(outputs))
	for i, item := range outputs {
		if item == nil || len(item.Beef) == 0 {
			slog.Warn("lookup: skipping an answer output with no BEEF", "position", i, "outputIndex", indexOf(item))
			continue
		}
		txid, err := subjectTxid(item.Beef)
		if err != nil {
			slog.Warn("lookup: skipping an answer output whose BEEF cannot be parsed",
				"position", i, "outputIndex", item.OutputIndex, "error", err)
			continue
		}
		usable = append(usable, answerOutput{item: item, txid: *txid})
	}
	return usable
}

// go-sdk's BEEF parser and serialiser, as variables so that a test can make
// them panic: no input known today does, so the recovers around them could
// not be tested otherwise.
var (
	parseAnswerBEEF    = transaction.NewTransactionFromBEEF
	serialiseAggregate = (*transaction.Beef).Bytes
	buildAggregate     = aggregateOutputs
)

// subjectTxid returns the txid of the transaction beef carries, turning a
// panic in go-sdk's parser into an error.
func subjectTxid(beef []byte) (txid *chainhash.Hash, err error) {
	defer func() {
		if r := recover(); r != nil {
			txid, err = nil, fmt.Errorf("BEEF parse panicked: %v", r)
		}
	}()
	tx, err := parseAnswerBEEF(beef)
	if err != nil {
		return nil, err
	}
	if txid = tx.TxID(); txid == nil {
		return nil, errors.New("nil txid from tx")
	}
	return txid, nil
}

// aggregateOutputs builds the binary aggregated answer for outputs. It fails
// at the first output whose BEEF cannot be merged, and when the merged BEEF
// cannot be written.
func aggregateOutputs(outputs []answerOutput) ([]byte, error) {
	header := new(bytes.Buffer)
	writeVarInt(header, uint64(len(outputs)))
	aggregated := transaction.NewBeef()
	for _, out := range outputs {
		// Emit the txid in DISPLAY (big-endian) byte order. The canonical
		// writer (OverlayExpress.ts) writes `tx.id()` — @bsv/sdk display
		// order — and BOTH canonical readers (@bsv/sdk LookupResolver and
		// go-sdk's facilitator) hex-encode these 32 bytes and then find the
		// tx in the BEEF by that hex; BEEF is indexed by the DISPLAY txid.
		// go-sdk's chainhash.Hash stores the internal (reversed) order, so we
		// reverse it here. Emitting internal order made every @bsv/sdk
		// LookupResolver throw "<txid> does not exist in this Beef" (reported
		// by a canonical-client integrator), a false-empty for a real hit.
		for i := len(out.txid) - 1; i >= 0; i-- {
			header.WriteByte(out.txid[i])
		}
		writeVarInt(header, uint64(out.item.OutputIndex))
		// Context is a TS-only extension; Go canonical writes 0.
		writeVarInt(header, 0)

		if err := mergeOutputBEEF(aggregated, out.item.Beef); err != nil {
			return nil, fmt.Errorf("merge the BEEF of %s:%d into the aggregate: %w", out.txid, out.item.OutputIndex, err)
		}
	}
	beefBytes, err := aggregatedBytes(aggregated)
	if err != nil {
		return nil, fmt.Errorf("serialise aggregated BEEF: %w", err)
	}
	return append(header.Bytes(), beefBytes...), nil
}

// mergeOutputBEEF merges beef into aggregated, turning a panic into an error.
// After a failure aggregated may hold part of beef, so it must not be used.
func mergeOutputBEEF(aggregated *transaction.Beef, beef []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("BEEF merge panicked: %v", r)
		}
	}()
	return aggregated.MergeBeefBytes(beef)
}

// aggregatedBytes serialises the aggregated BEEF, turning a panic into an
// error.
func aggregatedBytes(aggregated *transaction.Beef) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("BEEF serialisation panicked: %v", r)
		}
	}()
	return serialiseAggregate(aggregated)
}

// writePerOutputAnswer answers with outputs as a JSON output-list, each output
// with its own BEEF, as a /lookup without x-aggregation does. Each BEEF is
// written as an array of byte values, the canonical JSON shape (vector
// overlay.lookup.1; ts-stack's OverlayExpress), not as the base64 string
// encoding/json writes for a []byte: @bsv/sdk's LookupResolver reads JSON for
// any Content-Type other than application/octet-stream and drops an output
// whose beef is not an array, and go-sdk's facilitator decodes either form
// into []byte. The answer is streamed, so it never sits in memory whole.
func writePerOutputAnswer(w http.ResponseWriter, outputs []answerOutput) error {
	if perOutputAnswerSize(outputs) > routeguard.LookupAllowance {
		return fmt.Errorf("lookup response is over %d bytes", routeguard.LookupAllowance)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriterSize(w, 32<<10)
	bw.WriteString(`{"type":` + strconv.Quote(string(lookup.AnswerTypeOutputList)) + `,"outputs":[`)
	num := make([]byte, 0, 20)
	for i, out := range outputs {
		if i > 0 {
			bw.WriteByte(',')
		}
		bw.WriteString(`{"beef":[`)
		for j, b := range out.item.Beef {
			if j > 0 {
				bw.WriteByte(',')
			}
			bw.Write(strconv.AppendUint(num[:0], uint64(b), 10))
		}
		bw.WriteString(`],"outputIndex":`)
		bw.Write(strconv.AppendUint(num[:0], uint64(out.item.OutputIndex), 10))
		bw.WriteByte('}')
	}
	bw.WriteString("]}\n")
	return bw.Flush()
}

func perOutputAnswerSize(outputs []answerOutput) int64 {
	const head = `{"type":"output-list","outputs":[`
	const itemHead = `{"beef":[`
	const itemMiddle = `],"outputIndex":`
	const tail = "]}\n"
	size := int64(len(head) + len(tail))
	for i, out := range outputs {
		if i > 0 {
			size++
		}
		size += int64(len(itemHead) + len(itemMiddle) + len(strconv.FormatUint(uint64(out.item.OutputIndex), 10)) + 1)
		for j, b := range out.item.Beef {
			if j > 0 {
				size++
			}
			size += decimalByteLen(b)
			if size > routeguard.LookupAllowance {
				return size
			}
		}
	}
	return size
}

func decimalByteLen(b byte) int64 {
	if b < 10 {
		return 1
	}
	if b < 100 {
		return 2
	}
	return 3
}

// writeVarInt encodes a uint64 as a Bitcoin-flavoured variable-length
// integer onto buf. Mirrors readVarInt in handlers.go.
func writeVarInt(buf *bytes.Buffer, v uint64) {
	switch {
	case v < 0xfd:
		buf.WriteByte(byte(v))
	case v <= 0xffff:
		buf.WriteByte(0xfd)
		var tmp [2]byte
		binary.LittleEndian.PutUint16(tmp[:], uint16(v))
		buf.Write(tmp[:])
	case v <= 0xffffffff:
		buf.WriteByte(0xfe)
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], uint32(v))
		buf.Write(tmp[:])
	default:
		buf.WriteByte(0xff)
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], v)
		buf.Write(tmp[:])
	}
}

// indexOf returns the OutputIndex from an item or -1 if the item is
// nil. Used only for error messages.
func indexOf(item *lookup.OutputListItem) int {
	if item == nil {
		return -1
	}
	return int(item.OutputIndex)
}
