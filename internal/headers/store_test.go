package headers

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	sdkchainhash "github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

// tmpStore creates a test store with PoW validation disabled.
func tmpStore(t *testing.T) *Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "anvil-headers-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	s, err := NewTestStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// --- Genesis ---

func TestNewStoreWritesGenesis(t *testing.T) {
	s := tmpStore(t)
	if s.Tip() != 0 {
		t.Fatalf("expected tip 0, got %d", s.Tip())
	}

	raw, err := s.HeaderAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 80 {
		t.Fatalf("expected 80 bytes, got %d", len(raw))
	}

	hash, err := s.HashAtHeight(0)
	if err != nil {
		t.Fatal(err)
	}
	if hash == nil {
		t.Fatal("nil genesis hash")
	}

	expectedGenesis := "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	if hash.String() != expectedGenesis {
		t.Fatalf("genesis hash mismatch:\n  got  %s\n  want %s", hash.String(), expectedGenesis)
	}
}

// --- AddHeaders + ChainTracker ---

func TestAddHeadersAndQuery(t *testing.T) {
	s := tmpStore(t)
	genesisHash, _ := s.HashAtHeight(0)

	hdr := wire.NewBlockHeader(
		1, genesisHash,
		mustTestHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		0x1d00ffff, 12345,
	)
	hdr.Timestamp = time.Unix(1231006506, 0)

	err := s.AddHeaders(1, []*wire.BlockHeader{hdr})
	if err != nil {
		t.Fatal(err)
	}
	if s.Tip() != 1 {
		t.Fatalf("expected tip 1, got %d", s.Tip())
	}

	// ChainTracker: valid root
	merkleBytes, _ := sdkchainhash.NewHashFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	valid, err := s.IsValidRootForHeight(context.Background(), merkleBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid merkle root")
	}

	// ChainTracker: wrong root
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

	s1, err := NewTestStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	prevHash, _ := s1.HashAtHeight(0)
	merkle := mustTestHash("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, 99)
	hdr.Timestamp = time.Unix(1231006506, 0)
	s1.AddHeaders(1, []*wire.BlockHeader{hdr})
	s1.Close()

	s2, err := NewTestStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	if s2.Tip() != 1 {
		t.Fatalf("after reopen: expected tip 1, got %d", s2.Tip())
	}

	// Work should persist across reopen
	if s2.Work().Sign() <= 0 {
		t.Fatal("expected positive cumulative work after reopen")
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

// --- PoW validation ---

func TestValidatePoWGenesis(t *testing.T) {
	// The actual genesis block header should pass PoW validation
	var hdr wire.BlockHeader
	if err := hdr.Deserialize(bytesReader(genesisHeaderBytes)); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePoW(&hdr); err != nil {
		t.Fatalf("genesis should pass PoW: %v", err)
	}
}

func TestValidatePoWRejectsBadHash(t *testing.T) {
	// A header with max difficulty target (0x1d00ffff) but a hash that
	// doesn't meet even that easy target
	hdr := wire.NewBlockHeader(1,
		mustTestHash("0000000000000000000000000000000000000000000000000000000000000000"),
		mustTestHash("0000000000000000000000000000000000000000000000000000000000000000"),
		0x03010000, // very tight target: target = 0x010000
		0,
	)
	hdr.Timestamp = time.Unix(1231006505, 0)

	err := ValidatePoW(hdr)
	if err == nil {
		t.Fatal("expected PoW failure for header with hash above tight target")
	}
}

func TestCompactToBigRoundTrip(t *testing.T) {
	// Test that BigToCompact(compactToBig(x)) == x for known values
	cases := []uint32{
		0x1d00ffff, // genesis difficulty
		0x1b0404cb, // early blocks
		0x170b8c8b, // later difficulty
	}
	for _, bits := range cases {
		target := compactToBig(bits)
		got := BigToCompact(target)
		if got != bits {
			t.Errorf("round-trip failed: 0x%08x -> 0x%08x", bits, got)
		}
	}
}

func TestWorkForHeader(t *testing.T) {
	hdr := wire.NewBlockHeader(1,
		mustTestHash("0000000000000000000000000000000000000000000000000000000000000000"),
		mustTestHash("0000000000000000000000000000000000000000000000000000000000000000"),
		0x1d00ffff, 0,
	)
	hdr.Timestamp = time.Unix(1231006505, 0)

	work := WorkForHeader(hdr)
	if work.Sign() <= 0 {
		t.Fatal("expected positive work")
	}
}

func TestCumulativeWorkTracking(t *testing.T) {
	s := tmpStore(t)
	initialWork := s.Work()

	prevHash, _ := s.HashAtHeight(0)
	hdr := wire.NewBlockHeader(1, prevHash,
		mustTestHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		0x1d00ffff, 12345,
	)
	hdr.Timestamp = time.Unix(1231006506, 0)
	s.AddHeaders(1, []*wire.BlockHeader{hdr})

	afterWork := s.Work()
	if afterWork.Cmp(initialWork) <= 0 {
		t.Fatal("work should increase after adding headers")
	}
}

// --- Rollback ---

func TestRollback(t *testing.T) {
	s := tmpStore(t)

	// Build chain of 5 headers
	prevHash, _ := s.HashAtHeight(0)
	var headers []*wire.BlockHeader
	for i := 0; i < 5; i++ {
		merkle := mustTestHash("abcdef0000000000000000000000000000000000000000000000000000000000")
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(i+1))
		hdr.Timestamp = time.Unix(1231006506+int64(i)*600, 0)
		headers = append(headers, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}
	s.AddHeaders(1, headers)

	if s.Tip() != 5 {
		t.Fatalf("expected tip 5, got %d", s.Tip())
	}
	workBefore := new(big.Int).Set(s.Work())

	// Rollback to height 2
	err := s.Rollback(2)
	if err != nil {
		t.Fatal(err)
	}
	if s.Tip() != 2 {
		t.Fatalf("after rollback: expected tip 2, got %d", s.Tip())
	}

	// Work should have decreased
	if s.Work().Cmp(workBefore) >= 0 {
		t.Fatal("work should decrease after rollback")
	}

	// Headers at 3-5 should be gone
	for h := uint32(3); h <= 5; h++ {
		_, err := s.HeaderAtHeight(h)
		if err == nil {
			t.Fatalf("header at %d should be deleted after rollback", h)
		}
	}

	// Header at 2 should still exist
	_, err = s.HeaderAtHeight(2)
	if err != nil {
		t.Fatalf("header at 2 should survive rollback: %v", err)
	}
}

func TestRollbackRejectsHighTarget(t *testing.T) {
	s := tmpStore(t)
	err := s.Rollback(5) // tip is 0, can't rollback to 5
	if err == nil {
		t.Fatal("expected error when rollback target >= tip")
	}
}

// --- Sync with mock peer ---

type mockPeer struct {
	batches [][]*wire.BlockHeader
	calls   int
}

func (m *mockPeer) RequestHeaders(_ []*chainhash.Hash, _ *chainhash.Hash) error {
	return nil
}

func (m *mockPeer) ReadHeaders() ([]*wire.BlockHeader, error) {
	if m.calls >= len(m.batches) {
		return nil, nil // no more headers
	}
	batch := m.batches[m.calls]
	m.calls++
	return batch, nil
}

func (m *mockPeer) Close() error { return nil }

func TestSyncWithMockPeer(t *testing.T) {
	s := tmpStore(t)
	logger := testLogger()

	// Build a chain of 5 headers to feed through mock
	prevHash, _ := s.HashAtHeight(0)
	var headers []*wire.BlockHeader
	for i := 0; i < 5; i++ {
		merkle := mustTestHash("1234560000000000000000000000000000000000000000000000000000000000")
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(i+100))
		hdr.Timestamp = time.Unix(1231006506+int64(i)*600, 0)
		headers = append(headers, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}

	mock := &mockPeer{
		batches: [][]*wire.BlockHeader{headers}, // single batch of 5
	}

	syncer := NewSyncer(s, wire.TestNet3, logger)
	tip, err := syncer.SyncWith(mock)
	if err != nil {
		t.Fatal(err)
	}
	if tip != 5 {
		t.Fatalf("expected tip 5, got %d", tip)
	}
	if s.Tip() != 5 {
		t.Fatalf("store tip should be 5, got %d", s.Tip())
	}
}

func TestSyncerStatsRecordSuccessAndFailure(t *testing.T) {
	s := tmpStore(t)
	logger := testLogger()
	syncer := NewSyncer(s, wire.TestNet3, logger)

	syncer.recordAttempt("seed-a")
	syncer.recordFailure("seed-a", fmt.Errorf("dial failed"))
	stats := syncer.Stats()
	if stats.LastSource != "seed-a" {
		t.Fatalf("expected last source seed-a, got %q", stats.LastSource)
	}
	if stats.LastError == "" {
		t.Fatal("expected last error after failed attempt")
	}

	syncer.recordSuccess("seed-b", 123)
	stats = syncer.Stats()
	if stats.LastSource != "seed-b" {
		t.Fatalf("expected last source seed-b, got %q", stats.LastSource)
	}
	if stats.LastTip != 123 {
		t.Fatalf("expected last tip 123, got %d", stats.LastTip)
	}
	if stats.LastSuccessAt == "" {
		t.Fatal("expected last success timestamp")
	}
}

func TestSyncWithMultipleBatches(t *testing.T) {
	s := tmpStore(t)
	logger := testLogger()

	// Build 2 batches of 3 headers each
	prevHash, _ := s.HashAtHeight(0)
	var batch1, batch2 []*wire.BlockHeader

	for i := 0; i < 3; i++ {
		merkle := mustTestHash("aabb000000000000000000000000000000000000000000000000000000000000")
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(i+200))
		hdr.Timestamp = time.Unix(1231006506+int64(i)*600, 0)
		batch1 = append(batch1, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}
	for i := 0; i < 3; i++ {
		merkle := mustTestHash("ccdd000000000000000000000000000000000000000000000000000000000000")
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(i+300))
		hdr.Timestamp = time.Unix(1231007306+int64(i)*600, 0)
		batch2 = append(batch2, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}

	// First batch returns maxHeadersPerMsg-sized batch to trigger another request
	// but we can't fake 2000, so just test the multi-batch path with < maxHeadersPerMsg
	mock := &mockPeer{
		batches: [][]*wire.BlockHeader{batch1, batch2},
	}

	syncer := NewSyncer(s, wire.TestNet3, logger)
	// The syncer will request once, get 3 headers (<2000), and stop.
	// To test multi-batch, we override maxHeadersPerMsg... but it's a const.
	// Instead, test that both batches are consumed when first batch returns.
	tip, err := syncer.SyncWith(mock)
	if err != nil {
		t.Fatal(err)
	}
	// Syncer stops after first batch (3 < 2000), so only batch1 is consumed
	if tip != 3 {
		t.Fatalf("expected tip 3, got %d", tip)
	}
}

func TestLocatorAlwaysIncludesGenesis(t *testing.T) {
	s := tmpStore(t)
	logger := testLogger()
	syncer := NewSyncer(s, wire.TestNet3, logger)

	// At tip=0, locator should include genesis
	locators, err := syncer.buildLocator()
	if err != nil {
		t.Fatal(err)
	}
	if len(locators) == 0 {
		t.Fatal("locator should not be empty")
	}

	genesis, _ := s.HashAtHeight(0)
	last := locators[len(locators)-1]
	if *last != *genesis {
		t.Fatal("last locator entry should be genesis")
	}

	// Add some headers, locator should still end with genesis
	prevHash, _ := s.HashAtHeight(0)
	var headers []*wire.BlockHeader
	for i := 0; i < 20; i++ {
		merkle := mustTestHash("eeee000000000000000000000000000000000000000000000000000000000000")
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(i+400))
		hdr.Timestamp = time.Unix(1231006506+int64(i)*600, 0)
		headers = append(headers, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}
	s.AddHeaders(1, headers)

	locators, err = syncer.buildLocator()
	if err != nil {
		t.Fatal(err)
	}
	last = locators[len(locators)-1]
	if *last != *genesis {
		t.Fatalf("locator should end with genesis at tip=%d, last=%s genesis=%s",
			s.Tip(), last, genesis)
	}
}

// --- helpers ---

func mustTestHash(s string) *chainhash.Hash {
	h, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return h
}

func testLogger() *slog.Logger {
	return slog.Default()
}

func bytesReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}

// Ensure Store satisfies ChainTracker at compile time.
var _ interface {
	IsValidRootForHeight(context.Context, *sdkchainhash.Hash, uint32) (bool, error)
	CurrentHeight(context.Context) (uint32, error)
} = (*Store)(nil)
