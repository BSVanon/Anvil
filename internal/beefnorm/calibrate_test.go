package beefnorm

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// peakHeap runs f with garbage collection at 2% and returns the most heap
// allocated while it ran, above the heap before it, sampled every 50
// microseconds (beefscan's liveHeap, smaller). Uncollected garbage counts, so
// it can only read high.
func peakHeap(f func() any) uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(2))
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	base := m.HeapAlloc
	var top atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&m)
			for old := top.Load(); m.HeapAlloc > old && !top.CompareAndSwap(old, m.HeapAlloc); old = top.Load() {
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	runtime.KeepAlive(f())
	close(stop)
	<-done
	if t := top.Load(); t > base {
		return t - base
	}
	return 0
}

// hashAt is a pseudo-random node hash.
func hashAt(seed, i uint64) *chainhash.Hash {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	binary.LittleEndian.PutUint64(b[8:], i)
	h := chainhash.Hash(sha256.Sum256(b[:]))
	return &h
}

// flatBlock is a BEEF of one single-level BUMP of n leaves at offsets 0 to
// n-1, k of them parents a subject spends, spread over the leaves, and a
// tracker knowing the root go-sdk computes for it: the shape whose root
// computation over raw leaves costs the most per leaf (its synthesis of each
// unpaired node rescans level 0, merklepath.go:62-71).
func flatBlock(t testing.TB, n, k int) ([]byte, beefnormtest.Tracker) {
	t.Helper()
	yes := true
	level := make([]*transaction.PathElement, n)
	for i := range level {
		level[i] = &transaction.PathElement{Offset: uint64(i), Hash: hashAt(40, uint64(i))} //nolint:gosec // i >= 0
	}
	parents := make([]*transaction.Transaction, k)
	for i := range parents {
		parents[i] = beefnormtest.Parent(uint64(n)<<20|uint64(i), 1, 1000) //nolint:gosec // small
		el := level[i*(n/k)]
		el.Hash, el.Txid = parents[i].TxID(), &yes
	}
	path := transaction.NewMerklePath(800300, [][]*transaction.PathElement{level})
	root, err := path.ComputeRoot(parents[0].TxID())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range parents {
		p.MerklePath = path
	}
	s := beefnormtest.Spend(parents...)
	return beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{path}, parents...), beefnormtest.Tracker{800300: root}
}

// tallBlocks is a BEEF of m BUMPs at distinct heights, each declaring 255
// levels and proving one parent with a duplicate mark at every level above
// level 0, and a subject spending the m parents: as many path elements in
// the canonical BEEF as in the bytes, at two bytes each in the bytes.
func tallBlocks(t testing.TB, m int) []byte {
	t.Helper()
	yes := true
	parents := make([]*transaction.Transaction, m)
	bumps := make([]*transaction.MerklePath, m)
	for i := range parents {
		parents[i] = beefnormtest.Parent(1<<40|uint64(i), 1, 1000) //nolint:gosec // i >= 0
		levels := make([][]*transaction.PathElement, 255)
		levels[0] = []*transaction.PathElement{{Offset: 0, Hash: parents[i].TxID(), Txid: &yes}, {Offset: 1, Duplicate: &yes}}
		for h := 1; h < 255; h++ {
			levels[h] = []*transaction.PathElement{{Offset: 1, Duplicate: &yes}}
		}
		bumps[i] = transaction.NewMerklePath(uint32(900000+i), levels) //nolint:gosec // i small
		parents[i].MerklePath = bumps[i]
	}
	return beefnormtest.Encode(t, transaction.BEEF_V2, beefnormtest.Spend(parents...), bumps, parents...)
}

// TestCalibrateRawPaths times proofOps on the raw-path shapes the leaves cap
// bounds and measures Parse's peak heap on them and on the proof-cost shapes
// with the most path elements, against the body's length. It runs only with
// BEEFNORM_CALIBRATE=1:
//
//	BEEFNORM_CALIBRATE=1 go test -run CalibrateRawPaths -v -timeout 30m ./internal/beefnorm/
func TestCalibrateRawPaths(t *testing.T) {
	if os.Getenv("BEEFNORM_CALIBRATE") == "" {
		t.Skip("set BEEFNORM_CALIBRATE=1 to calibrate")
	}
	leaves := beefscan.Default.Leaves
	type shape struct {
		name    string
		b       []byte
		tracker beefnormtest.Tracker
	}
	var shapes []shape
	for _, k := range []int{1, 1256} {
		b, tracker := flatBlock(t, leaves, k)
		shapes = append(shapes, shape{"one level of the leaves cap, " + strconv.Itoa(k) + " named", b, tracker})
	}
	b, tracker := fanIn(t, 1195, 20, spread)
	shapes = append(shapes, shape{"1,195 spread over 2^20, one compound BUMP", b, tracker})
	b, tracker = fanIn(t, 342, 255, separate)
	shapes = append(shapes, shape{"342 over 255 levels, a BUMP each", b, tracker})
	for _, s := range shapes {
		shape, err := beefscan.Inspect(s.b)
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		var worst [len(proofOps)]time.Duration
		for run := 0; run < 3; run++ {
			d := timeProofOps(t, s.b, s.tracker)
			for i := range worst {
				worst[i] = max(worst[i], d[i])
			}
		}
		op, d := slowest(worst)
		peak := peakHeap(func() any { n, _ := Parse(s.b); return n })
		t.Logf("%-46s %8d B, leaves %6d, proof cost %8d | %v | slowest %s %v | Parse peak %6.1f MB, %5.2fx the body",
			s.name, len(s.b), shape.Leaves, shape.ProofCost, worst, op, d, float64(peak)/1e6, float64(peak)/float64(len(s.b)))
	}
	tall := tallBlocks(t, leaves/256)
	peak := peakHeap(func() any { n, err := Parse(tall); return []any{n, err} })
	n, err := Parse(tall)
	if err != nil {
		t.Fatal(err)
	}
	var elements int
	for _, p := range n.Beef.BUMPs {
		for _, level := range p.Path {
			elements += len(level)
		}
	}
	t.Logf("%d BUMPs of 255 duplicate levels: %d B, %d canonical path elements, Parse peak %.1f MB, %.2fx the body",
		leaves/256, len(tall), elements, float64(peak)/1e6, float64(peak)/float64(len(tall)))
}
