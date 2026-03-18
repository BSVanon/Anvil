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

func TestStoreBUMPAndRetrieve(t *testing.T) {
	s := tmpProofStore(t)
	txid := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	bump := []byte{0x01, 0x02, 0x03, 0x04}

	err := s.StoreBUMP(txid, bump)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetBUMP(txid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(bump) {
		t.Fatalf("expected %d bytes, got %d", len(bump), len(got))
	}
	for i := range bump {
		if got[i] != bump[i] {
			t.Fatalf("byte %d: expected %02x, got %02x", i, bump[i], got[i])
		}
	}
}

func TestStoreRawTxAndRetrieve(t *testing.T) {
	s := tmpProofStore(t)
	txid := "1111111111111111111111111111111111111111111111111111111111111111"
	raw := []byte{0x01, 0x00, 0x00, 0x00} // minimal tx version bytes

	err := s.StoreRawTx(txid, raw)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetRawTx(txid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(raw) {
		t.Fatalf("expected %d bytes, got %d", len(raw), len(got))
	}
}

func TestHasProof(t *testing.T) {
	s := tmpProofStore(t)
	txid := "2222222222222222222222222222222222222222222222222222222222222222"

	if s.HasProof(txid) {
		t.Fatal("should not have proof for unknown txid")
	}

	s.StoreBUMP(txid, []byte{0x01})
	if !s.HasProof(txid) {
		t.Fatal("should have proof after storing")
	}
}

func TestGetBUMPNotFound(t *testing.T) {
	s := tmpProofStore(t)
	_, err := s.GetBUMP("0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected error for missing BUMP")
	}
}
