package storage

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// malformedBEEFBumpIndex builds a BEEF_V1 blob with ZERO BUMPs but a single
// transaction that claims merkle-bump index 5 — so go-sdk's reader does
// BUMPs[5] on a length-0 slice and PANICS. This reproduces the field crash
// behind the DEX-swap lookup 502 ("index out of range [210] with length 1").
func malformedBEEFBumpIndex() []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, transaction.BEEF_V1) // version
	buf.WriteByte(0x00)                                              // nBUMPs = 0 → BUMPs length 0
	buf.WriteByte(0x01)                                              // numberOfTransactions = 1
	// minimal empty tx: version=1, 0 inputs, 0 outputs, locktime=0 (10 bytes)
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	buf.WriteByte(0x01) // hasBump = 1
	buf.WriteByte(0x05) // pathIndex = 5 → BUMPs[5] panics
	return buf.Bytes()
}

// TestSafeNewBeefFromBytes_RecoversPanic is the regression for the DEX-swap
// lookup 502: a corrupt stored BEEF made go-sdk's NewBeefFromBytes panic deep
// inside lookup hydration, crashing the request (502 via the proxy on the
// dropped connection). safeNewBeefFromBytes must turn that panic into an
// ordinary error.
func TestSafeNewBeefFromBytes_RecoversPanic(t *testing.T) {
	beef, err := safeNewBeefFromBytes(malformedBEEFBumpIndex()) // must NOT panic
	if err == nil {
		t.Fatal("expected an error for a panic-inducing BEEF blob")
	}
	if beef != nil {
		t.Fatalf("expected nil beef on failure, got %v", beef)
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("expected the recover path (error mentions 'panicked'), got: %v", err)
	}
}

// TestSafeNewBeefFromBytes_ErrorsOnGarbage confirms ordinary malformed input
// (not panic-inducing) still returns an error and never panics.
func TestSafeNewBeefFromBytes_ErrorsOnGarbage(t *testing.T) {
	for _, blob := range [][]byte{nil, {0x00}, {0xff, 0xff, 0xff, 0xff}, []byte("not beef at all")} {
		if _, err := safeNewBeefFromBytes(blob); err == nil {
			t.Fatalf("expected error for garbage blob %x", blob)
		}
	}
}

// TestHydrate_CorruptBEEF_SkipsGracefully is the end-to-end fix: a stored output
// whose BEEF blob is corrupt must not crash (or fail) the lookup. FindOutput
// returns the output with a nil Beef — which the engine drops from results — so
// the query still returns every other (valid) offer.
func TestHydrate_CorruptBEEF_SkipsGracefully(t *testing.T) {
	s, db := newStore(t)
	txid := makeHash(0x77)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0}, nil, nil, nil); err != nil {
		t.Fatalf("insert outputs: %v", err)
	}
	// Plant a corrupt BEEF blob for this txid.
	if err := db.Put(beefKey(txid), malformedBEEFBumpIndex(), nil); err != nil {
		t.Fatalf("put corrupt beef: %v", err)
	}

	op := &transaction.Outpoint{Txid: *txid, Index: 0}
	topic := topicA
	out, err := s.FindOutput(ctxBg(), op, &topic, nil, true) // includeBEEF=true
	if err != nil {
		t.Fatalf("FindOutput must not fail on a corrupt BEEF; got: %v", err)
	}
	if out == nil {
		t.Fatal("expected a non-nil output")
	}
	if out.Beef != nil {
		t.Fatal("expected nil Beef for a corrupt blob (skipped, not hydrated)")
	}
}
