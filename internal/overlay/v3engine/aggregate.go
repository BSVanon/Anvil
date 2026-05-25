package v3engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// writeAggregatedAnswer serialises a LookupAnswer in the binary
// aggregation format required by vector overlay.lookup.3:
//
//	varint(numOutpoints) +
//	foreach[ txid(32 bytes LE) + varint(outputIndex) +
//	         varint(contextLen) + context ] +
//	BEEF bytes (single BEEF holding every output's tx)
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
	outputs := answer.Outputs
	if outputs == nil {
		// Empty result — still valid; write a 0-count header + empty
		// BEEF marker so the canonical client always sees a parseable
		// payload.
		outputs = nil
	}

	header := new(bytes.Buffer)
	writeVarInt(header, uint64(len(outputs)))

	aggregated := transaction.NewBeef()
	for _, item := range outputs {
		if item == nil || len(item.Beef) == 0 {
			return fmt.Errorf("aggregated output missing BEEF (outputIndex=%d)", indexOf(item))
		}
		tx, err := transaction.NewTransactionFromBEEF(item.Beef)
		if err != nil {
			return fmt.Errorf("parse output BEEF: %w", err)
		}
		txid := tx.TxID()
		if txid == nil {
			return errors.New("nil txid from tx")
		}
		// vector says "txid(32 bytes LE)". chainhash.Hash is stored
		// LE internally, so the raw bytes are already correct.
		header.Write(txid[:])
		writeVarInt(header, uint64(item.OutputIndex))
		// Context is a TS-only extension; Go canonical writes 0.
		writeVarInt(header, 0)

		if err := aggregated.MergeBeefBytes(item.Beef); err != nil {
			return fmt.Errorf("merge BEEF into aggregate (outputIndex=%d): %w", item.OutputIndex, err)
		}
	}

	beefBytes, err := aggregated.Bytes()
	if err != nil {
		return fmt.Errorf("serialise aggregated BEEF: %w", err)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(header.Bytes()); err != nil {
		return err
	}
	_, err = w.Write(beefBytes)
	return err
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
