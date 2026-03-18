package headers

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	sdkchainhash "github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

func tmpStore(t *testing.T) *Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "anvil-headers-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewStoreWritesGenesis(t *testing.T) {
	s := tmpStore(t)
	if s.Tip() != 0 {
		t.Fatalf("expected tip 0, got %d", s.Tip())
	}

	// Genesis header should be retrievable
	raw, err := s.HeaderAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 80 {
		t.Fatalf("expected 80 bytes, got %d", len(raw))
	}

	// Hash at height 0 should work
	hash, err := s.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if hash == nil {
		t.Fatal("nil genesis hash")
	}

	// Known BSV genesis hash (same as BTC)
	expectedGenesis := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	if hash.String() != expectedGenesis {
		t.Fatalf("genesis hash mismatch:\n  got  %s\n  want %s", hash.String(), expectedGenesis)
	}
}

func TestAddHeadersAndQuery(t *testing.T) {
	s := tmpStore(t)

	// Get genesis hash for prev-block linkage
	genesisHash, _ := s.HashAtHeight(0)

	// Create a fake header linking to genesis
	hdr := wire.NewBlockHeader(
		1,
		genesisHash,
		mustTestHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		0x1d00ffff,
		12345,
	)
	hdr.Timestamp = time.Unix(1231006506, 0)

	err := s.AddHeaders(1, []*wire.BlockHeader{hdr})
	if err != nil {
		t.Fatal(err)
	}

	if s.Tip() != 1 {
		t.Fatalf("expected tip 1, got %d", s.Tip())
	}

	// Query merkle root via ChainTracker
	merkleBytes, _ := sdkchainhash.NewHashFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	valid, err := s.IsValidRootForHeight(context.Background(), merkleBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid merkle root")
	}

	// Wrong root should be invalid
	wrongRoot, _ := sdkchainhash.NewHashFromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	valid, err = s.IsValidRootForHeight(context.Background(), wrongRoot, 1)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected invalid merkle root")
	}
}

func TestAddHeadersRejectsBadPrevHash(t *testing.T) {
	s := tmpStore(t)

	// Create a header with wrong prev-hash
	wrongPrev := mustTestHash("1111111111111111111111111111111111111111111111111111111111111111")
	hdr := wire.NewBlockHeader(1, wrongPrev, wrongPrev, 0x1d00ffff, 0)
	hdr.Timestamp = time.Unix(1231006506, 0)

	err := s.AddHeaders(1, []*wire.BlockHeader{hdr})
	if err == nil {
		t.Fatal("expected error for bad prev-hash")
	}
}

func TestAddHeadersRejectsBadStartHeight(t *testing.T) {
	s := tmpStore(t)

	genesisHash, _ := s.HashAtHeight(0)
	hdr := wire.NewBlockHeader(1, genesisHash, genesisHash, 0x1d00ffff, 0)
	hdr.Timestamp = time.Unix(1231006506, 0)

	// Start at height 5 when tip is 0 — should fail
	err := s.AddHeaders(5, []*wire.BlockHeader{hdr})
	if err == nil {
		t.Fatal("expected error for wrong start height")
	}
}

func TestCurrentHeight(t *testing.T) {
	s := tmpStore(t)
	h, err := s.CurrentHeight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h != 0 {
		t.Fatalf("expected 0, got %d", h)
	}
}

func TestChainOfHeaders(t *testing.T) {
	s := tmpStore(t)

	// Build a chain of 10 headers
	prevHash, _ := s.HashAtHeight(0)
	var headers []*wire.BlockHeader

	for i := 0; i < 10; i++ {
		merkle := mustTestHash("abcdef0000000000000000000000000000000000000000000000000000000000")
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(i))
		hdr.Timestamp = time.Unix(1231006506+int64(i)*600, 0)
		headers = append(headers, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}

	err := s.AddHeaders(1, headers)
	if err != nil {
		t.Fatal(err)
	}

	if s.Tip() != 10 {
		t.Fatalf("expected tip 10, got %d", s.Tip())
	}

	// Verify height lookup works for all
	for i := uint32(0); i <= 10; i++ {
		_, err := s.HeaderAtHeight(i)
		if err != nil {
			t.Fatalf("header at %d: %v", i, err)
		}
	}
}

func TestReopenStore(t *testing.T) {
	dir, err := os.MkdirTemp("", "anvil-headers-reopen-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Open, add a header, close
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	prevHash, _ := s1.HashAtHeight(0)
	merkle := mustTestHash("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, 99)
	hdr.Timestamp = time.Unix(1231006506, 0)
	s1.AddHeaders(1, []*wire.BlockHeader{hdr})
	s1.Close()

	// Reopen — should have tip=1
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if s2.Tip() != 1 {
		t.Fatalf("after reopen: expected tip 1, got %d", s2.Tip())
	}
}

func TestIsValidRootForMissingHeight(t *testing.T) {
	s := tmpStore(t)
	root, _ := sdkchainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	valid, err := s.IsValidRootForHeight(context.Background(), root, 999)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected invalid for missing height")
	}
}

func mustTestHash(s string) *chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return h
}

// Ensure Store satisfies the interface at compile time.
var _ interface {
	IsValidRootForHeight(context.Context, *sdkchainhash.Hash, uint32) (bool, error)
	CurrentHeight(context.Context) (uint32, error)
} = (*Store)(nil)

// Suppress unused import
var _ = bytes.Compare
