package storage

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// hugeCountVarint is a 9-byte CompactSize/VarInt encoding (0xFF prefix, then
// an 8-byte little-endian value) of 2^36. Every case below uses it to make a
// wire-supplied element count or byte length declare far more than the bytes
// that actually follow it, so the count exceeds remaining bytes.
func hugeCountVarint() []byte {
	return []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}
}

// merklePathHugeLeafCount builds a standalone BUMP: blockHeight=0,
// treeHeight=1, nLeaves=2^36, padded to the 37-byte minimum
// NewMerklePathFromBinary requires before it will attempt to parse at all.
func merklePathHugeLeafCount() []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x00)          // blockHeight varint = 0
	buf.WriteByte(0x01)          // treeHeight = 1
	buf.Write(hugeCountVarint()) // nLeavesAtThisHeight varint: count exceeds remaining bytes
	buf.Write(make([]byte, 26))  // padding to satisfy the 37-byte minimum length check
	return buf.Bytes()
}

// beefHugeBUMPCount builds a BEEF V1 prefix whose BUMP count exceeds the
// (zero) bytes left after it.
func beefHugeBUMPCount() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0xBE, 0xEF}) // BEEF_V1 version marker
	buf.Write(hugeCountVarint())              // numberOfBUMPs varint: count exceeds remaining bytes
	return buf.Bytes()
}

// beefHugeTxCountV2 builds a BEEF V2 prefix with zero BUMPs, then a
// transaction count exceeding the bytes left after it (the readBeefTx path).
func beefHugeTxCountV2() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0x00, 0xBE, 0xEF}) // BEEF_V2 version marker
	buf.WriteByte(0x00)                       // numberOfBUMPs = 0
	buf.Write(hugeCountVarint())              // numberOfTransactions varint: count exceeds remaining bytes
	return buf.Bytes()
}

// beefHugeTxCountV1 builds a BEEF V1 prefix with zero BUMPs, then a
// transaction count exceeding the bytes left after it (the
// readAllTransactions path).
func beefHugeTxCountV1() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0xBE, 0xEF}) // BEEF_V1 version marker
	buf.WriteByte(0x00)                       // numberOfBUMPs = 0
	buf.Write(hugeCountVarint())              // numberOfTransactions varint: count exceeds remaining bytes
	return buf.Bytes()
}

// txHugeInputCount builds a bare transaction header whose input count
// exceeds the bytes left after it.
func txHugeInputCount() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version = 1
	buf.Write(hugeCountVarint())              // inputCount varint: count exceeds remaining bytes
	return buf.Bytes()
}

// txHugeOutputCount builds a transaction header with zero inputs, then an
// output count exceeding the bytes left after it.
func txHugeOutputCount() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version = 1
	buf.WriteByte(0x00)                       // inputCount = 0
	buf.Write(hugeCountVarint())              // outputCount varint: count exceeds remaining bytes
	return buf.Bytes()
}

// txHugeInputScriptLen builds a transaction with one input (txid + output
// index only), then an unlocking-script length exceeding the bytes left
// after it.
func txHugeInputScriptLen() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version = 1
	buf.WriteByte(0x01)                       // inputCount = 1
	buf.Write(make([]byte, 32))               // input previous txid
	buf.Write(make([]byte, 4))                // input previous output index
	buf.Write(hugeCountVarint())              // unlocking script length varint: count exceeds remaining bytes
	return buf.Bytes()
}

// txHugeInputSourceScriptLen builds an extended-format transaction (the
// 0x000000EF marker, big-endian, after zero inputs/outputs) with one input
// whose source-output script length exceeds the bytes left after it.
func txHugeInputSourceScriptLen() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version = 1
	buf.WriteByte(0x00)                       // inputCount = 0
	buf.WriteByte(0x00)                       // outputCount = 0
	buf.Write([]byte{0x00, 0x00, 0x00, 0xEF}) // extended-format marker (big-endian 0xEF)
	buf.WriteByte(0x01)                       // real inputCount = 1
	buf.Write(make([]byte, 32))               // input previous txid
	buf.Write(make([]byte, 4))                // input previous output index
	buf.WriteByte(0x00)                       // unlocking script length = 0
	buf.Write(make([]byte, 4))                // sequence
	buf.Write(make([]byte, 8))                // previous output satoshis (extended)
	buf.Write(hugeCountVarint())              // source script length varint: count exceeds remaining bytes
	return buf.Bytes()
}

// txHugeOutputScriptLen builds a transaction with zero inputs and one
// output (satoshis only), then a locking-script length exceeding the bytes
// left after it.
func txHugeOutputScriptLen() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version = 1
	buf.WriteByte(0x00)                       // inputCount = 0
	buf.WriteByte(0x01)                       // outputCount = 1
	buf.Write(make([]byte, 8))                // output satoshis
	buf.Write(hugeCountVarint())              // locking script length varint: count exceeds remaining bytes
	return buf.Bytes()
}

// transactionsHugeTxCount is a bare transaction count exceeding the (zero)
// bytes left after it, for transaction.Transactions.ReadFrom.
func transactionsHugeTxCount() []byte {
	return hugeCountVarint()
}

// TestParseGuard_RejectsOversizedWireCounts is the v3.4.1 security
// regression for wire-sized allocations. go-sdk v1.2.23 sized slices directly
// from varints read off the wire, so a crafted BEEF or transaction whose
// declared element count or byte length exceeds the bytes actually present
// drove an out-of-memory crash before any data was validated. go-sdk v1.5.0+
// bounds each such count against the remaining bytes before allocating
// (transaction/parse_guard.go: guardParseCount and readGuardedBytes). Each
// case below hits one guarded site with a minimal input whose declared count
// exceeds the remaining bytes. It must get that guard's ordinary error, which
// names the site and says "exceeds capacity", never a panic or a crash.
func TestParseGuard_RejectsOversizedWireCounts(t *testing.T) {
	cases := []struct {
		name  string
		data  []byte
		parse func([]byte) error
		site  string // the guarded site's label in go-sdk's error text
	}{
		{"merkle path leaves (direct BUMP)", merklePathHugeLeafCount(), func(b []byte) error {
			_, err := transaction.NewMerklePathFromBinary(b)
			return err
		}, "merkle path leaves count"},
		{
			// BEEF V1, 1 BUMP, block height 0, tree height 1, nLeaves=2^36 —
			// the exact 16-byte input reachable with no login via POST /submit.
			"merkle path leaves (16-byte BEEF V1 submit)",
			[]byte{0x01, 0x00, 0xBE, 0xEF, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00},
			func(b []byte) error {
				_, _, _, err := transaction.ParseBeef(b)
				return err
			},
			"merkle path leaves count",
		},
		{"BEEF BUMPs count", beefHugeBUMPCount(), func(b []byte) error {
			_, err := transaction.NewBeefFromBytes(b)
			return err
		}, "BEEF BUMPs count"},
		{"BEEF transactions count (V2 path)", beefHugeTxCountV2(), func(b []byte) error {
			_, err := transaction.NewBeefFromBytes(b)
			return err
		}, "BEEF transactions count"},
		{"BEEF transactions count (V1 path)", beefHugeTxCountV1(), func(b []byte) error {
			_, err := transaction.NewTransactionFromBEEF(b)
			return err
		}, "BEEF transactions count"},
		{"transaction input count", txHugeInputCount(), func(b []byte) error {
			_, err := transaction.NewTransactionFromBytes(b)
			return err
		}, "inputs count"},
		{"transaction output count", txHugeOutputCount(), func(b []byte) error {
			_, err := transaction.NewTransactionFromBytes(b)
			return err
		}, "outputs count"},
		{"input unlocking script length", txHugeInputScriptLen(), func(b []byte) error {
			_, err := transaction.NewTransactionFromBytes(b)
			return err
		}, "input script count"},
		{"input source script length (extended format)", txHugeInputSourceScriptLen(), func(b []byte) error {
			_, err := transaction.NewTransactionFromBytes(b)
			return err
		}, "input source script count"},
		{"output locking script length", txHugeOutputScriptLen(), func(b []byte) error {
			_, err := transaction.NewTransactionFromBytes(b)
			return err
		}, "output locking script count"},
		{
			// Not reachable from BEEF/transaction parsing in Anvil today
			// (nothing here calls transaction.Transactions.ReadFrom), but it
			// is still a guarded site in go-sdk and deserves its own direct
			// regression.
			"Transactions.ReadFrom transaction count",
			transactionsHugeTxCount(),
			func(b []byte) error {
				var txs transaction.Transactions
				_, err := txs.ReadFrom(bytes.NewReader(b))
				return err
			},
			"transactions count",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parse panicked instead of returning an error: %v", r)
				}
			}()
			err := tc.parse(tc.data)
			if err == nil {
				t.Fatalf("expected an error for an oversized wire count, got nil")
			}
			if !strings.Contains(err.Error(), tc.site) || !strings.Contains(err.Error(), "exceeds capacity") {
				t.Fatalf("expected the %q guard to report %q, got: %v", tc.site, "exceeds capacity", err)
			}
		})
	}
}
