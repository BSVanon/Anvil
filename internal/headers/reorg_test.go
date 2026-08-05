package headers

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

const (
	saltA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	saltB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// buildChain returns n synthetic headers linked from prevHash. The merkle salt
// + nonce base make two chains grown from the same fork point distinct (so they
// genuinely compete). Returns the headers and the hash of the final one. All
// headers share Bits=0x1d00ffff, so with skipPoW test stores their cumulative
// work is proportional to chain length — letting tests control "heavier" by
// making a fork longer than the range it replaces.
func buildChain(prevHash *chainhash.Hash, n int, salt string, nonceBase uint32) ([]*wire.BlockHeader, *chainhash.Hash) {
	hdrs := make([]*wire.BlockHeader, 0, n)
	ph := prevHash
	for i := 0; i < n; i++ {
		hdr := wire.NewBlockHeader(1, ph, mustTestHash(salt), 0x1d00ffff, nonceBase+uint32(i))
		hdr.Timestamp = time.Unix(1231006506+int64(i)*600, 0)
		hdrs = append(hdrs, hdr)
		h := hdr.BlockHash()
		ph = &h
	}
	return hdrs, ph
}

func TestReorgTo_AdoptsHeavierFork(t *testing.T) {
	s := tmpStore(t)
	genesis, _ := s.HashAtHeight(0)

	// Main chain: heights 1..5.
	main, _ := buildChain(genesis, 5, saltA, 1000)
	if err := s.AddHeaders(1, main); err != nil {
		t.Fatalf("seed main chain: %v", err)
	}
	workBefore := s.Work()

	// Competing chain forks at height 3 and extends to height 7:
	// 4 new headers replace the 2 (heights 4,5) we discard → strictly heavier.
	forkPoint, _ := s.HashAtHeight(3)
	fork, forkTip := buildChain(forkPoint, 4, saltB, 5000)

	adopted, forkHeight, err := s.ReorgTo(fork)
	if err != nil {
		t.Fatalf("ReorgTo: %v", err)
	}
	if !adopted {
		t.Fatal("expected the heavier fork to be adopted")
	}
	if forkHeight != 3 {
		t.Fatalf("forkHeight = %d, want 3", forkHeight)
	}
	if s.Tip() != 7 {
		t.Fatalf("tip = %d, want 7", s.Tip())
	}
	got, _ := s.HashAtHeight(7)
	if *got != *forkTip {
		t.Fatalf("tip hash is not the fork tip:\n got  %s\n want %s", got, forkTip)
	}
	// The orphaned height-4 block must no longer be indexed by hash.
	oldH4 := main[3].BlockHash()
	if _, err := s.HeightForHash(&oldH4); err == nil {
		t.Fatal("orphaned height-4 hash should have been removed")
	}
	if s.Work().Cmp(workBefore) <= 0 {
		t.Fatal("cumulative work should have increased after adopting a heavier chain")
	}
}

func TestReorgTo_RefusesLighterFork(t *testing.T) {
	s := tmpStore(t)
	genesis, _ := s.HashAtHeight(0)

	main, _ := buildChain(genesis, 5, saltA, 1000)
	if err := s.AddHeaders(1, main); err != nil {
		t.Fatal(err)
	}

	// Fork at height 3 with a single header (height 4) — shorter than the two
	// (heights 4,5) it would replace, so not heavier.
	forkPoint, _ := s.HashAtHeight(3)
	fork, _ := buildChain(forkPoint, 1, saltB, 5000)

	adopted, forkHeight, err := s.ReorgTo(fork)
	if err != nil {
		t.Fatalf("a valid lighter fork should be refused cleanly, got err: %v", err)
	}
	if adopted {
		t.Fatal("must not adopt a lighter fork")
	}
	if forkHeight != 3 {
		t.Fatalf("forkHeight = %d, want 3", forkHeight)
	}
	if s.Tip() != 5 {
		t.Fatalf("tip must be unchanged at 5, got %d", s.Tip())
	}
}

func TestReorgTo_RefusesTooDeepFork(t *testing.T) {
	s := tmpStore(t)
	genesis, _ := s.HashAtHeight(0)

	// Chain of 150 so a fork at height 2 has depth 148 > maxReorgDepth (144).
	main, _ := buildChain(genesis, 150, saltA, 1000)
	if err := s.AddHeaders(1, main); err != nil {
		t.Fatal(err)
	}

	forkPoint, _ := s.HashAtHeight(2)
	fork, _ := buildChain(forkPoint, 200, saltB, 5000)

	adopted, _, err := s.ReorgTo(fork)
	if err == nil {
		t.Fatal("expected an error for a fork deeper than maxReorgDepth")
	}
	if adopted {
		t.Fatal("must not adopt a too-deep fork")
	}
	if s.Tip() != 150 {
		t.Fatalf("tip must be unchanged at 150, got %d", s.Tip())
	}
}

func TestReorgTo_RefusesUnknownForkPoint(t *testing.T) {
	s := tmpStore(t)
	genesis, _ := s.HashAtHeight(0)
	main, _ := buildChain(genesis, 5, saltA, 1000)
	if err := s.AddHeaders(1, main); err != nil {
		t.Fatal(err)
	}

	// Competing headers whose parent is a hash we've never seen.
	orphan := mustTestHash("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	fork, _ := buildChain(orphan, 3, saltB, 5000)

	adopted, _, err := s.ReorgTo(fork)
	if err == nil {
		t.Fatal("expected an error for an unknown fork point")
	}
	if adopted {
		t.Fatal("must not adopt a fork with an unknown parent")
	}
	if s.Tip() != 5 {
		t.Fatalf("tip must be unchanged at 5, got %d", s.Tip())
	}
}

// TestAddHeaders_PrevHashMismatchIsDetectable locks in two contracts the rest
// of the system depends on: the syncer switches on errors.Is(ErrPrevHashMismatch)
// to trigger a reorg, and `anvil doctor` / /status detect a stuck store by the
// literal "prev hash mismatch" substring in the last sync error. A refactor
// that drops either would silently re-open the multi-day-stall failure mode.
func TestAddHeaders_PrevHashMismatchIsDetectable(t *testing.T) {
	s := tmpStore(t)
	genesis, _ := s.HashAtHeight(0)
	main, _ := buildChain(genesis, 3, saltA, 1000)
	if err := s.AddHeaders(1, main); err != nil {
		t.Fatal(err)
	}

	// A header at the next height that does not link to the tip.
	nonLinking, _ := buildChain(mustTestHash("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), 1, saltB, 9000)
	err := s.AddHeaders(4, nonLinking)
	if err == nil {
		t.Fatal("expected a prev-hash mismatch error")
	}
	if !errors.Is(err, ErrPrevHashMismatch) {
		t.Fatalf("error must wrap ErrPrevHashMismatch (the syncer's reorg trigger): %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "prev hash mismatch") {
		t.Fatalf("error must contain \"prev hash mismatch\" (anvil doctor / /status detection): %v", err)
	}
}

func TestAddHeaders_MidBatchLinkageMismatchIsNotReorgSignal(t *testing.T) {
	s := tmpStore(t)
	genesis, _ := s.HashAtHeight(0)

	first, _ := buildChain(genesis, 1, saltA, 1000)
	nonLinking, _ := buildChain(mustTestHash("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), 1, saltB, 9000)

	err := s.AddHeaders(1, []*wire.BlockHeader{first[0], nonLinking[0]})
	if err == nil {
		t.Fatal("expected an error for a malformed in-batch linkage")
	}
	if errors.Is(err, ErrPrevHashMismatch) {
		t.Fatalf("mid-batch linkage failure must not be treated as a tip-reorg signal: %v", err)
	}
	if s.Tip() != 0 {
		t.Fatalf("failed batch must not partially commit; tip = %d, want 0", s.Tip())
	}
}

// TestSyncWith_RecoversFromReorg reproduces the production incident: the store's
// tip sits on a minority fork, and the peer serves the heavier main chain that
// diverges below the tip. The old syncer got permanently stuck here (prev-hash
// mismatch → froze for days). It must now self-heal by adopting the heavier
// chain, with no error.
func TestSyncWith_RecoversFromReorg(t *testing.T) {
	s := tmpStore(t)
	logger := testLogger()
	genesis, _ := s.HashAtHeight(0)

	// Local store is on a minority fork: heights 1..5 (the "loser" tip).
	loser, _ := buildChain(genesis, 5, saltA, 1000)
	if err := s.AddHeaders(1, loser); err != nil {
		t.Fatal(err)
	}

	// The peer serves the heavier main chain: forks at height 3, extends to 8.
	forkPoint, _ := s.HashAtHeight(3)
	winner, winnerTip := buildChain(forkPoint, 5, saltB, 5000)

	mock := &mockPeer{batches: [][]*wire.BlockHeader{winner}}
	syncer := NewSyncer(s, wire.TestNet3, logger)

	tip, err := syncer.SyncWith(mock)
	if err != nil {
		t.Fatalf("SyncWith must recover from a tip reorg, got: %v", err)
	}
	if tip != 8 {
		t.Fatalf("expected tip 8 after reorg, got %d", tip)
	}
	got, _ := s.HashAtHeight(8)
	if *got != *winnerTip {
		t.Fatal("post-reorg tip is not the winning chain")
	}
}
