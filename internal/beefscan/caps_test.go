package beefscan

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// opBound is the test bound on every go-sdk call for the worst accepted shape
// of each cap. The calibration target is 1 s; calibrate_test.go measures it.
const opBound = 2 * time.Second

// refuseBound is the test bound on Check refusing a hostile shape.
const refuseBound = 50 * time.Millisecond

// boundary pins one cap where Default was calibrated: at is its shape
// family's value at the cap, the worst accepted shape, and at+1 the first
// past it. The caps are literals, not Default's fields, so raising one in
// Default leaves the shape past it accepted, and the test fails.
type boundary struct {
	limit string
	cap   uint64
	at    int
	build func(v2 bool, n int) []byte
	v1    bool // whether the family has a V1 form
	value func(Shape) uint64
}

var boundaries = []boundary{
	{"transactions", 10000, 10000, func(_ bool, n int) []byte { return txsShape(n) }, false, func(s Shape) uint64 { return uint64(s.Txs) }},
	{"inputs", 100000, 100000, inputsShape, true, func(s Shape) uint64 { return uint64(s.Inputs) }},
	{"outputs", 250000, 250000, outputsShape, true, func(s Shape) uint64 { return uint64(s.Outputs) }},
	{"BUMPs", 10000, 10000, bumpsShape, true, func(s Shape) uint64 { return uint64(s.BUMPs) }},
	{"leaves", 200000, 200000, leavesShape, true, func(s Shape) uint64 { return uint64(s.Leaves) }},
	// (60+1) * 16,385 = 999,485; (61+1) * 16,385 = 1,015,870.
	{"combine cost", 1000000, 60, combineShape, true, func(s Shape) uint64 { return s.CombineCost }},
	// 1,414^2 = 1,999,396; 1,415^2 = 2,002,225.
	{"root cost", 2000000, 1414, rootShape, true, func(s Shape) uint64 { return s.RootCost }},
	// 7,071 * 14,141 = 99,991,011; 7,072 * 14,143 = 100,019,296.
	{"chain cost", 100000000, 7070, func(v2 bool, n int) []byte { return chainShape(v2, n, 0) }, true, func(s Shape) uint64 { return s.ChainCost }},
	// 1,000 * 10,000 = 10,000,000; 1,001 * 10,000 = 10,010,000.
	{"find cost", 10000000, 1000, func(_ bool, u int) []byte { return findShape(u, findBUMPs) }, false, func(s Shape) uint64 { return s.FindCost }},
}

func versions(v1 bool) []bool {
	if v1 {
		return []bool{false, true}
	}
	return []bool{true}
}

func version(v2 bool) string {
	if v2 {
		return "V2"
	}
	return "V1"
}

// refusedBy reports whether err is a refusal by the named limit.
func refusedBy(err error, limit string) bool {
	return errors.Is(err, ErrTooComplex) && strings.HasPrefix(err.Error(), ErrTooComplex.Error()+": "+limit+" ")
}

// TestCapBoundaries proves each cap where it was calibrated: the worst shape
// at the cap is accepted and every go-sdk call on it finishes inside opBound,
// and the next shape past it is refused by that cap alone.
func TestCapBoundaries(t *testing.T) {
	for _, c := range boundaries {
		t.Run(c.limit, func(t *testing.T) {
			for _, v2 := range versions(c.v1) {
				at, next := c.build(v2, c.at), c.build(v2, c.at+1)
				if got := c.value(Scan(at)); got > c.cap || got < c.cap-c.cap/100 {
					t.Errorf("%s: the shape at the cap has %d, not within 1%% under %d", version(v2), got, c.cap)
				}
				if err := Check(at); err != nil {
					t.Errorf("%s: the worst accepted shape is refused: %v", version(v2), err)
				}
				if err := Check(next); !refusedBy(err, c.limit) {
					t.Errorf("%s: one past the cap, got %v, want a refusal by %s", version(v2), err, c.limit)
				}
				if raceEnabled {
					continue
				}
				times := fastestOf(at, 2, opBound)
				if op, d := times.slowest(); d > opBound {
					t.Errorf("%s: %s took %v on the worst accepted shape, over %v", version(v2), op, d, opBound)
				}
				t.Logf("%s %d bytes: %v", version(v2), len(at), times)
			}
		})
	}
}

// TestWorstAcceptedShapesAreFast times the accepted shapes that sit at two
// caps at once, or that measured slower per unit than a boundary family.
func TestWorstAcceptedShapesAreFast(t *testing.T) {
	if raceEnabled {
		t.Skip("timing bounds do not hold under the race detector")
	}
	shapes := map[string]func(v2 bool) []byte{
		"10,000 unproven empty transactions (transactions and chain caps)": func(v2 bool) []byte { return emptyTxs(v2, 10000) },
		"chain of 3,014 with 9 more inputs each (chain cap)":               func(v2 bool) []byte { return chainShape(v2, 3014, 9) },
		"100 txids each over 20,000 leaves (root cap)":                     func(v2 bool) []byte { return wideRoot(v2, 100, 20000) },
	}
	for name, build := range shapes {
		for _, v2 := range []bool{false, true} {
			b := build(v2)
			if err := Check(b); err != nil {
				t.Fatalf("%s %s: refused: %v", name, version(v2), err)
			}
			times := fastestOf(b, 2, opBound)
			if op, d := times.slowest(); d > opBound {
				t.Errorf("%s %s: %s took %v, over %v", name, version(v2), op, d, opBound)
			}
		}
	}
}

// wideRoot is a one-level BUMP of n leaves whose first t are flagged as
// txids, named by one parent: root cost t*n.
func wideRoot(v2 bool, t, n int) []byte {
	level := make([]leaf, n)
	for i := range level {
		level[i] = leaf{offset: uint64(i), hash: node(16, uint64(i))}
		if i < t {
			level[i].flags = 2
		}
	}
	entries, _ := fanIn(1, func(int) int { return 0 })
	return beefBytes(v2, [][]byte{bump(block, [][]leaf{level})}, entries)
}

// hostile are the shapes the red-team review found, and the other blowups
// the costs model, each well past one cap. Unrefused, smaller instances of
// the cost shapes already take one go-sdk call 0.17 to 3.1 s
// (TestCalibrateCaps), and these larger ones grow quadratically from there;
// at the expansion TestCalibrateHeap measures for each element at 4 MiB, the
// 64 MiB shapes would hold 0.28 GB (inputs) to 1.48 GB (duplicate leaves).
var hostile = []struct {
	name, limit string
	build       func() []byte
}{
	{"red team: same-height BUMPs, a proof of one block per parent, V1", "combine cost", func() []byte { return sameBlockFanIn(false, 3000) }},
	{"red team: same-height BUMPs, a proof of one block per parent, V2", "combine cost", func() []byte { return sameBlockFanIn(true, 3000) }},
	{"red team: same-height BUMPs, a proof of one block each, one named, V2", "combine cost", func() []byte { return sameBlockBUMPs(3000) }},
	{"red team: transactions sharing one wide BUMP, V1", "combine cost", func() []byte { return combineShape(false, 1000) }},
	{"transactions sharing one wide BUMP, Atomic", "combine cost", func() []byte {
		entries, subject := fanIn(1000, func(int) int { return 0 })
		return atomicBEEF(subject, beefBytes(false, [][]byte{compoundBUMP(block, combineLeaves, 0, 1)}, entries))
	}},
	{"transactions sharing one BUMP of 200,000 leaves, V1", "combine cost", func() []byte {
		entries, _ := fanIn(5000, func(int) int { return 0 })
		return beefBytes(false, [][]byte{compoundBUMP(block, 200000, 0, 1)}, entries)
	}},
	{"transactions sharing the tallest duplicate path, V1", "combine cost", func() []byte { return tallPathFanIn(9000) }},
	{"every leaf of a wide BUMP a txid", "root cost", func() []byte { return rootShape(true, 4096) }},
	{"a long unproven chain with wide inputs", "chain cost", func() []byte { return chainShape(true, 9000, 9) }},
	{"an Atomic proof search over every BUMP", "find cost", func() []byte { return findShape(7000, findBUMPs) }},
	{"reviewer: 64 MiB V2 BEEF of empty transactions", "transactions", func() []byte { return hugeEmptyTxs(64 << 20) }},
	{"64 MiB of txid-only entries", "transactions", func() []byte { return hugeTxids(64 << 20) }},
	{"64 MiB of duplicate leaves", "leaves", func() []byte { return hugeDupLeaves(64 << 20) }},
	{"64 MiB of one-leaf BUMPs", "BUMPs", func() []byte { return hugeBUMPs(64 << 20) }},
	{"64 MiB of outputs", "outputs", func() []byte { return hugeOutputs(64 << 20) }},
	{"64 MiB of inputs", "inputs", func() []byte { return hugeInputs(64 << 20) }},
}

func TestHostileShapesRefusedFast(t *testing.T) {
	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			b := h.build()
			var err error
			d := elapsed(func() { err = Check(b) })
			if d > refuseBound { // one retry: the machine is shared
				d = min(d, elapsed(func() { err = Check(b) }))
			}
			if !refusedBy(err, h.limit) {
				t.Errorf("got %v, want a refusal by %s", err, h.limit)
			}
			if !raceEnabled && d > refuseBound {
				t.Errorf("refused in %v, over %v", d, refuseBound)
			}
			t.Logf("%d bytes refused in %v: %v", len(b), d, err)
		})
	}
}
