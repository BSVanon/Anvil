package spv

import (
	"os"
	"testing"
)

func tmpProofStore(t *testing.T) *ProofStore {
	t.Helper()
	dir, err := os.MkdirTemp("", "anvil-proofstore-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	s, err := NewProofStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStoreBEEFAndRetrieve(t *testing.T) {
	s := tmpProofStore(t)

	// Use a minimal synthetic BEEF-like payload for store/retrieve round-trip.
	// The store doesn't validate — it just persists bytes.
	fakeTxid := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	fakeBeef := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// Direct key storage for round-trip test
	key := append(append([]byte{}, prefixBeef...), []byte(fakeTxid)...)
	s.db.Put(key, fakeBeef, nil)

	got, err := s.GetBEEF(fakeTxid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(fakeBeef) {
		t.Fatalf("expected %d bytes, got %d", len(fakeBeef), len(got))
	}
	for i := range fakeBeef {
		if got[i] != fakeBeef[i] {
			t.Fatalf("byte %d: expected %02x, got %02x", i, fakeBeef[i], got[i])
		}
	}
}

func TestHasBEEF(t *testing.T) {
	s := tmpProofStore(t)
	txid := "2222222222222222222222222222222222222222222222222222222222222222"

	if s.HasBEEF(txid) {
		t.Fatal("should not have BEEF for unknown txid")
	}

	key := append(append([]byte{}, prefixBeef...), []byte(txid)...)
	s.db.Put(key, []byte{0x01}, nil)

	if !s.HasBEEF(txid) {
		t.Fatal("should have BEEF after storing")
	}
}

func TestGetBEEFNotFound(t *testing.T) {
	s := tmpProofStore(t)
	_, err := s.GetBEEF("0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error for missing BEEF")
	}
}
