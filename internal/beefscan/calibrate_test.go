package beefscan

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"testing"
)

// The calibration behind Default. It is slow and memory heavy (up to about
// 400 MB of heap), so it runs only with BEEFSCAN_CALIBRATE=1, alone:
//
//	BEEFSCAN_CALIBRATE=1 go test -run Calibrate -v -timeout 30m ./internal/beefscan/

func calibrating(t *testing.T) {
	t.Helper()
	if os.Getenv("BEEFSCAN_CALIBRATE") == "" {
		t.Skip("set BEEFSCAN_CALIBRATE=1 to calibrate")
	}
	if raceEnabled {
		t.Skip("calibration needs a build without the race detector")
	}
}

// worstOf runs timeOps n times and keeps each call's slowest time.
func worstOf(b []byte, n int) opTimes {
	var worst opTimes
	for i := 0; i < n; i++ {
		d := timeOps(b)
		for j := range worst {
			worst[j] = max(worst[j], d[j])
		}
	}
	return worst
}

func row(t *testing.T, name string, b []byte) {
	t.Helper()
	s := Scan(b)
	d := worstOf(b, 3)
	peak := parseHeap(b)
	t.Logf("%-52s %9d B | BUMPs %5d leaves %6d txs %5d in %6d out %6d | proof %9d chain %9d find %8d | %v | heap %.1f MB %.1fx | %v",
		name, len(b), s.BUMPs, s.Leaves, s.Txs, s.Inputs, s.Outputs, s.ProofCost, s.ChainCost, s.FindCost,
		d, float64(peak)/1e6, float64(peak)/float64(len(b)), Check(b))
}

// TestCalibrateCaps times the parse the routes run on untrusted bytes
// (sdkOps), the slowest of three runs, and measures ParseBeef's peak heap, on
// the worst accepted shape of each cap, the accepted shapes at two caps at
// once, and the legitimate fixtures. beefnorm's calibration times the calls
// on the normalized BEEF.
func TestCalibrateCaps(t *testing.T) {
	calibrating(t)
	t.Logf("calls: %v", sdkOps)
	for _, c := range boundaries {
		for _, v2 := range versions(c.v1) {
			row(t, fmt.Sprintf("%s at the cap, %s", c.limit, version(v2)), c.build(v2, c.at))
		}
	}
	for _, v2 := range []bool{false, true} {
		row(t, "10,000 unproven empty txs, "+version(v2), emptyTxs(v2, 10000))
		row(t, "chain of 3,014 with 9 more inputs each, "+version(v2), chainShape(v2, 3014, 9))
	}
	// Refused shapes, one run each, to show what the costs hold back; the
	// larger instances in caps_test.go's hostile list cost more again.
	for name, b := range map[string][]byte{
		"refused: 3,000 same-block proofs, V1":        sameBlockFanIn(false, 3000),
		"refused: chain of 9,000, 9 more inputs each": chainShape(true, 9000, 9),
		"refused: 7,000 unproven over 10,000 BUMPs":   findShape(7000, findBUMPs),
		"refused: 9,000 sharing the tallest path, V1": tallPathFanIn(9000),
	} {
		s := Scan(b)
		t.Logf("%-52s %9d B | proof %10d chain %9d find %8d | %v | %v", name, len(b),
			s.ProofCost, s.ChainCost, s.FindCost, timeOps(b), Check(b))
	}
	fixtures := legitimate(t)
	names := make([]string, 0, len(fixtures))
	for name := range fixtures {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		row(t, name, fixtures[name])
	}
}

// unlockTx is a transaction spending id:0 with an unlocking script of n bytes.
func unlockTx(id [32]byte, n int) []byte {
	var w wire
	w.u32(1)
	w.varint(1)
	w.Write(id[:])
	w.u32(0)
	w.varint(uint64(n)) //nolint:gosec // n is positive
	w.Write(make([]byte, n))
	w.u32(0xffffffff)
	w.varint(1)
	_ = binary.Write(&w, binary.LittleEndian, uint64(1))
	w.varint(0)
	w.u32(0)
	return w.Bytes()
}

// scriptShape is a proven parent and a subject whose bytes are almost all
// script, about size bytes in all.
func scriptShape(v2 bool, size int, where string) []byte {
	raw, id, proof := spent()
	n := size - 200
	var sub []byte
	switch where {
	case "one output script":
		sub = rawTx(1, []outpoint{{txid: id}}, []int{n})
	case "1 KiB output scripts":
		outs := make([]int, n/1033)
		for i := range outs {
			outs[i] = 1024
		}
		sub = rawTx(1, []outpoint{{txid: id}}, outs)
	case "one unlocking script":
		sub = unlockTx(id, n)
	case "one EF source script":
		sub = efTx([]outpoint{{txid: id}}, n, []int{0})
	}
	return beefBytes(v2, [][]byte{proof}, []entry{{raw: raw, bump: 0}, {raw: sub, bump: -1}})
}

// dense picks a variant of denseShape.
type dense struct {
	txs, inputs int
	tall        bool // each BUMP 20 levels of one duplicate leaf, not one level of 20
	ef          bool // the subject in extended format, each input with an empty source script
}

// denseShape is the most parse heap per byte found inside Default, at about
// size bytes: 10,000 BUMPs at distinct heights of 20 duplicate leaves each
// (the BUMPs and leaves caps), d.txs empty transactions each naming one of
// them, and a subject with up to d.inputs inputs and up to 249,999 empty
// outputs, as many as fit, and one output script filling the rest. Every cost
// stays inside Default for 9,999 transactions with no inputs (chain cost
// exactly 10,000^2) and for 989 with 99,000 inputs (990 * 99,990).
func denseShape(v2 bool, size int, d dense) []byte {
	level := make([]leaf, 20)
	for i := range level {
		level[i] = leaf{flags: 1}
	}
	levels := [][]leaf{level}
	if d.tall {
		levels = make([][]leaf, 20)
		for i := range levels {
			levels[i] = level[:1]
		}
	}
	bumps := make([][]byte, 10000)
	for i := range bumps {
		bumps[i] = bump(uint64(i)+1, levels)
	}
	entries := make([]entry, 0, d.txs+1)
	for i := 0; i < d.txs; i++ {
		entries = append(entries, entry{raw: emptyTx(uint32(i) + 2), bump: i}) //nolint:gosec // i < 2^32
	}
	inSize := 41
	if d.ef {
		inSize = 50
	}
	used := len(beefBytes(v2, bumps, entries)) + 64 // the subject's fixed bytes, with room to spare
	nIn := min(d.inputs, max(0, size-used)/inSize)
	used += inSize * nIn
	nOut := min(249999, max(0, size-used)/9)
	used += 9 * nOut
	ins := make([]outpoint, nIn)
	for i := range ins {
		ins[i] = outpoint{txid: sha256d(entries[0].raw)}
	}
	outs := append(make([]int, nOut), max(0, size-used))
	sub := rawTx(1, ins, outs)
	if d.ef {
		sub = efTx(ins, 0, outs)
	}
	return beefBytes(v2, bumps, append(entries, entry{raw: sub, bump: -1}))
}

// TestCalibrateHeap measures ParseBeef's peak heap over body size for accepted
// shapes at 1, 8, 32 and 64 MiB: script-heavy shapes, and the densest
// structure the caps admit filled out with script. It also measures the raw
// expansion of each element the count caps limit, on 4 MiB shapes Check
// refuses, to show what each cap holds back.
func TestCalibrateHeap(t *testing.T) {
	calibrating(t)
	type shape struct {
		name  string
		build func(v2 bool, size int) []byte
	}
	var shapes []shape
	for name, d := range map[string]dense{
		"dense, 9,999 transactions":       {txs: 9999},
		"dense, 99,000 inputs":            {txs: 989, inputs: 99000},
		"dense, tall, 9,999 transactions": {txs: 9999, tall: true},
		"dense, tall, 99,000 EF inputs":   {txs: 989, inputs: 99000, tall: true, ef: true},
	} {
		shapes = append(shapes, shape{name, func(v2 bool, size int) []byte { return denseShape(v2, size, d) }})
	}
	for _, where := range []string{"one output script", "1 KiB output scripts", "one unlocking script", "one EF source script"} {
		shapes = append(shapes, shape{where, func(v2 bool, size int) []byte { return scriptShape(v2, size, where) }})
	}
	for _, mib := range []int{1, 8, 32, 64} {
		for _, s := range shapes {
			for _, v2 := range []bool{false, true} {
				b := s.build(v2, mib<<20)
				if err := Check(b); err != nil {
					t.Fatalf("%s %s at %d MiB is refused: %v", s.name, version(v2), mib, err)
				}
				peak := parseHeap(b)
				sh := Scan(b)
				t.Logf("%2d MiB %-26s %s %9d B txs %5d in %6d out %6d: peak %6.1f MB, %5.2fx",
					mib, s.name, version(v2), len(b), sh.Txs, sh.Inputs, sh.Outputs, float64(peak)/1e6, float64(peak)/float64(len(b)))
			}
		}
	}
	for name, b := range map[string][]byte{
		"empty transactions": hugeEmptyTxs(4 << 20), "txid-only entries": hugeTxids(4 << 20),
		"duplicate leaves": hugeDupLeaves(4 << 20), "one-leaf BUMPs": hugeBUMPs(4 << 20),
		"outputs": hugeOutputs(4 << 20), "inputs": hugeInputs(4 << 20),
	} {
		peak := parseHeap(b)
		sh := Scan(b)
		elems := sh.Txs + sh.BUMPs + sh.Leaves + sh.Inputs + sh.Outputs
		t.Logf("4 MiB of %-20s (refused: %v): peak %6.1f MB, %5.2fx, %3.0f B per element",
			name, Check(b) != nil, float64(peak)/1e6, float64(peak)/float64(len(b)), float64(peak)/float64(elems))
	}
}

// TestCalibrateSmallBodies looks for the highest heap over body size among
// accepted bodies under 1 MiB, where the densest elements dominate.
func TestCalibrateSmallBodies(t *testing.T) {
	calibrating(t)
	dupLeaves := func(v2 bool, n int) []byte {
		raw, id, _ := spent()
		level := make([]leaf, n)
		for i := range level {
			level[i].flags = 1 // a duplicate, with no hash
		}
		return beefBytes(v2, [][]byte{bump(block, [][]leaf{level})}, []entry{{raw: raw, bump: 0}, spender(id)})
	}
	for _, v2 := range []bool{false, true} {
		for _, n := range []int{10, 100, 1000, 3000, 10000} {
			b := emptyTxs(v2, n)
			t.Logf("%s %6d empty transactions %8d B: %5.2fx (%v)", version(v2), n, len(b), float64(parseHeap(b))/float64(len(b)), Check(b))
		}
		for _, n := range []int{100, 1000, 20000, 100000, 200000} {
			b := dupLeaves(v2, n)
			t.Logf("%s %6d duplicate leaves   %8d B: %5.2fx (%v)", version(v2), n, len(b), float64(parseHeap(b))/float64(len(b)), Check(b))
		}
		for _, tall := range []bool{false, true} {
			b := denseShape(v2, 0, dense{txs: 9999, tall: tall})
			t.Logf("%s dense core, tall %-5v %8d B: %5.2fx (%v)", version(v2), tall, len(b), float64(parseHeap(b))/float64(len(b)), Check(b))
		}
	}
}
