package beefnorm

import (
	"context"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// layout is how a fan-in's k parents sit in their one block.
type layout int

const (
	spread   layout = iota // offsets spread evenly over the whole block, one compound BUMP
	separate               // spread, a BUMP of its own for each parent
	grouped                // groups of four adjacent offsets, the groups spread, one compound BUMP
	band                   // offsets three apart, one compound BUMP
	packed                 // offsets 0 to k-1, one compound BUMP
)

func (l layout) String() string {
	return [...]string{"one compound BUMP", "a BUMP per parent", "groups of four", "three apart", "packed"}[l]
}

// fanIn is a subject spending k parents mined in one block of 2^levels
// transactions, as V2, and a tracker knowing the block. Offsets stay below
// 2^62, so a block of more levels declares more than its offsets need.
func fanIn(t testing.TB, k, levels int, l layout) ([]byte, beefnormtest.Tracker) {
	t.Helper()
	parents := make([]*transaction.Transaction, k)
	ids := make([]*chainhash.Hash, k)
	offsets := make([]uint64, k)
	idx := make([]int, k)
	span := uint64(1) << min(levels, 62)
	n := uint64(k) //nolint:gosec // k > 0
	for i := range parents {
		u := uint64(i)                                                                //nolint:gosec // i >= 0
		parents[i] = beefnormtest.Parent(uint64(levels)<<40|uint64(l)<<32|u, 1, 1000) //nolint:gosec // small
		ids[i], idx[i] = parents[i].TxID(), i
		switch l {
		case packed:
			offsets[i] = u
		case band:
			offsets[i] = 3 * u
		case grouped:
			offsets[i] = u/4*(span/((n+3)/4)) + u%4
		default:
			offsets[i] = u * (span / n)
		}
	}
	blk := beefnormtest.NewBlock(800100, levels, ids, offsets)
	var bumps []*transaction.MerklePath
	if l == separate {
		for i, p := range parents {
			p.MerklePath = blk.Proof(i)
			bumps = append(bumps, p.MerklePath)
		}
	} else {
		path := blk.Compound(idx...)
		for _, p := range parents {
			p.MerklePath = path
		}
		bumps = []*transaction.MerklePath{path}
	}
	s := beefnormtest.Spend(parents...)
	return beefnormtest.Encode(t, transaction.BEEF_V2, s, bumps, parents...), beefnormtest.Tracker{}.Add(blk)
}

// proofOps names the calls timed on a BEEF of the proof-cost family.
var proofOps = [...]string{"Inspect", "Parse", "spv.Verify", "Beef.Verify", "Atomic", "NewTransactionFromBEEF", "Clone+Bytes"}

// timeProofOps times each of proofOps on b, as the routes run them.
func timeProofOps(t testing.TB, b []byte, tracker beefnormtest.Tracker) (d [len(proofOps)]time.Duration) {
	t.Helper()
	ctx := context.Background()
	d[0] = elapsed(func() { _, _ = beefscan.Inspect(b) })
	var n *BEEF
	var err error
	d[1] = elapsed(func() { n, err = Parse(b) })
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	d[2] = elapsed(func() {
		if ok, err := spv.Verify(ctx, n.Tx, tracker, nil); !ok || err != nil {
			t.Errorf("spv.Verify: %v %v", ok, err)
		}
	})
	d[3] = elapsed(func() {
		if ok, err := n.Beef.Verify(ctx, tracker, false); !ok || err != nil {
			t.Errorf("Beef.Verify: %v %v", ok, err)
		}
	})
	var atomic []byte
	d[4] = elapsed(func() { atomic, err = n.Atomic() })
	if err != nil {
		t.Fatalf("Atomic: %v", err)
	}
	d[5] = elapsed(func() { _, err = transaction.NewTransactionFromBEEF(atomic) })
	if err != nil {
		t.Fatalf("NewTransactionFromBEEF: %v", err)
	}
	d[6] = elapsed(func() { _, err = n.Beef.Clone().Bytes() })
	if err != nil {
		t.Fatalf("Clone+Bytes: %v", err)
	}
	return d
}

func elapsed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

// slowest is the longest of d and the call that took it.
func slowest(d [len(proofOps)]time.Duration) (string, time.Duration) {
	i := 0
	for j := range d {
		if d[j] > d[i] {
			i = j
		}
	}
	return proofOps[i], d[i]
}

// TestConsolidationOfAThousandParents: an honest consolidation of 1,000
// parents from one block of 2^20 transactions, in V1, V2 and Atomic, is
// within beefscan.Default and normalizes to one BUMP that verifies; so does
// the same fan-in with a BUMP per parent. v3.4.0's combine cost refused 300.
func TestConsolidationOfAThousandParents(t *testing.T) {
	subject, parents, blk := beefnormtest.Consolidation(1000, 20, 800200)
	tracker := beefnormtest.Tracker{}.Add(blk)
	v1 := beefnormtest.Encode(t, transaction.BEEF_V1, subject, []*transaction.MerklePath{parents[0].MerklePath}, parents...)
	v2 := beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{parents[0].MerklePath}, parents...)
	separately, _ := fanIn(t, 1000, 20, separate)
	for name, b := range map[string][]byte{"V1": v1, "V2": v2, "Atomic": beefnormtest.Atomic(subject, v2)} {
		shape, err := beefscan.Inspect(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(n.Beef.BUMPs) != 1 || len(n.Beef.Transactions) != 1001 {
			t.Errorf("%s: %d BUMPs and %d entries", name, len(n.Beef.BUMPs), len(n.Beef.Transactions))
		}
		if ok, err := spv.Verify(context.Background(), n.Tx, tracker, nil); !ok || err != nil {
			t.Errorf("%s: spv.Verify: %v %v", name, ok, err)
		}
		t.Logf("%s: %d bytes, proof cost %d of %d", name, len(b), shape.ProofCost, beefscan.Default.ProofCost)
	}
	n, err := Parse(separately)
	if err != nil {
		t.Fatalf("a BUMP per parent: %v", err)
	}
	if len(n.Beef.BUMPs) != 1 {
		t.Errorf("a BUMP per parent: %d BUMPs after Parse, want 1", len(n.Beef.BUMPs))
	}
}

// TestCalibrateProofCost times proofOps, slowest of three runs, on fan-ins of
// every layout with as many parents as beefscan.Default's proof cost admits
// for the block's levels, and with 1,000 where it admits that many. It is
// slow, so it runs only with BEEFNORM_CALIBRATE=1:
//
//	BEEFNORM_CALIBRATE=1 go test -run CalibrateProofCost -v -timeout 30m ./internal/beefnorm/
func TestCalibrateProofCost(t *testing.T) {
	if os.Getenv("BEEFNORM_CALIBRATE") == "" {
		t.Skip("set BEEFNORM_CALIBRATE=1 to calibrate")
	}
	t.Logf("calls: %v", proofOps)
	for _, levels := range []int{11, 12, 16, 20, 24, 32, 48, 64, 128, 255} {
		capK := int(math.Sqrt(float64(beefscan.Default.ProofCost) / float64(levels+1)))
		for capK*capK*(levels+1) > int(beefscan.Default.ProofCost) {
			capK--
		}
		for _, l := range []layout{spread, separate, grouped, band, packed} {
			for _, k := range []int{1000, capK} {
				if k > capK || (k == 1000 && capK == 1000) || (levels < 62 && (k > 1<<levels || (l == band && 3*k > 1<<levels))) {
					continue
				}
				calibrate(t, k, levels, l)
			}
		}
	}
	fmt.Fprintln(os.Stderr, "calibration done")
}

func calibrate(t *testing.T, k, levels int, l layout) {
	t.Helper()
	b, tracker := fanIn(t, k, levels, l)
	shape, err := beefscan.Inspect(b)
	if err != nil {
		t.Fatalf("levels %d %s k %d: %v", levels, l, k, err)
	}
	var worst [len(proofOps)]time.Duration
	for run := 0; run < 3; run++ {
		d := timeProofOps(t, b, tracker)
		for i := range worst {
			worst[i] = max(worst[i], d[i])
		}
	}
	op, d := slowest(worst)
	t.Logf("levels %3d %-18s k %5d: proof cost %10d, %8d bytes | %v | slowest %s %v (%.2f ns per unit)",
		levels, l, k, shape.ProofCost, len(b), worst, op, d, float64(d.Nanoseconds())/float64(shape.ProofCost))
}
