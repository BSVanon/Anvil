package beefscan

import (
	"encoding/binary"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// margin is how far inside Default every legitimate fixture must sit: each
// passes with every cap divided by margin.
const margin = 5

func scaled(l Limits, div int) Limits {
	d := uint64(div) //nolint:gosec // a small positive constant
	return Limits{
		Txs: l.Txs / div, Inputs: l.Inputs / div, Outputs: l.Outputs / div, BUMPs: l.BUMPs / div, Leaves: l.Leaves / div,
		ProofCost: l.ProofCost / d, ChainCost: l.ChainCost / d, FindCost: l.FindCost / d,
	}
}

// TestLegitimateFixturesPass checks every honest fixture, in V1, V2 and
// Atomic form, against Default and against Default with a margin, and that
// each fixture is the shape its name says.
func TestLegitimateFixturesPass(t *testing.T) {
	shapes := map[string]struct{ bumps, txs int }{
		"SHIP and SLAP advertisements": {1, 2}, "DEX OrdLock listing": {2, 3}, "UMP token": {1, 2}, "KVStore token": {1, 2},
		"chain of 1,000 unproven from one proven root": {1, 1001},
		"1,000 inputs from distinct blocks":            {1000, 1001},
		"100 inputs from one block":                    {1, 101}, // one shared BUMP, in every encoding
	}
	tight := scaled(Default, margin)
	fixtures := legitimate(t)
	if len(fixtures) != 3*len(shapes) {
		t.Fatalf("%d fixtures, want %d", len(fixtures), 3*len(shapes))
	}
	for name, b := range fixtures {
		s := Scan(b)
		want := shapes[name[:strings.LastIndex(name, ", ")]]
		if s.BUMPs != want.bumps || s.Txs != want.txs {
			t.Errorf("%s: %d BUMPs and %d transactions, want %d and %d", name, s.BUMPs, s.Txs, want.bumps, want.txs)
		}
		if err := Check(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := tight.Check(b); err != nil {
			t.Errorf("%s passes Default but not with a %dx margin: %v", name, margin, err)
		}
		if _, _, _, err := transaction.ParseBeef(b); err != nil {
			t.Errorf("%s: go-sdk refuses the fixture itself: %v", name, err)
		}
		t.Logf("%-52s %7d B %+v", name, len(b), s)
	}
}

// fanInV1 is three proven parents sharing one four-leaf proof and a subject
// spending them: BUMPs 1, leaves 4, transactions 4, inputs 3, outputs 4,
// proof cost 3^2 * (3+1) = 36 (three levels, and offset 5 needs three), chain
// cost 4*(4+3) = 28, find cost 1*1.
func fanInV1() []byte {
	entries, _ := fanIn(3, func(int) int { return 0 })
	return beefBytes(false, [][]byte{proofBUMP(block, 3, 4, node(9, 9), 1)}, entries)
}

// oneLeafBUMPs is a V2 BEEF of n BUMPs at heights 1 to n, one duplicate leaf
// each, and one empty transaction naming the first.
func oneLeafBUMPs(n int) []byte {
	tail := append([]byte{1, 1, 0}, emptyTx(1)...)
	return huge(4+9+len(tail)+9*n, nil, 9, func(b []byte, i int) []byte {
		return append(binary.LittleEndian.AppendUint32(append(b, 0xfe), uint32(i)+1), 1, 1, 0, 1) //nolint:gosec // i < 2^32
	}, tail)
}

// overclaim is a V2 BEEF declaring 2^63-1 BUMPs, or with no BUMPs 2^63-1
// transactions, followed by three bytes.
func overclaim(bumps bool) []byte {
	b := binary.LittleEndian.AppendUint32(nil, transaction.BEEF_V2)
	if !bumps {
		b = append(b, 0)
	}
	return append(b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 1, 2, 3)
}

func TestScan(t *testing.T) {
	parent := rawTx(2, nil, []int{0})
	id := sha256d(parent)
	other := rawTx(3, nil, []int{0})
	pair := func(h uint64, txid bool, seed uint64) []byte {
		var flags byte
		if txid {
			flags = 2
		}
		return bump(h, [][]leaf{{{0, flags, node(seed, 0)}, {1, 0, node(seed, 1)}}})
	}
	bare := node(3, 3)
	spends := rawTx(1, []outpoint{{txid: id}, {txid: sha256d(other)}}, []int{0})
	cases := []struct {
		name string
		b    []byte
		want Shape
	}{
		{"empty input", nil, Shape{}},
		{"unknown version", []byte{1, 2, 3, 4, 5, 6}, Shape{}},
		{"Atomic prefix cut short", atomicBEEF(id, nil)[:20], Shape{Atomic: true}},
		{"a BUMP count past the bytes left", overclaim(true), Shape{Version: transaction.BEEF_V2}},
		{"a transaction count past the bytes left", overclaim(false), Shape{Version: transaction.BEEF_V2}},
		{"V1 fan-in on one shared proof", fanInV1(), Shape{Version: transaction.BEEF_V1, BUMPs: 1, Leaves: 4, Txs: 4, Inputs: 3, Outputs: 4,
			ProofCost: 36, ChainCost: 28, FindCost: 1}},
		{"Atomic V2 with a bare txid", atomicBEEF(id, beefBytes(true, [][]byte{proofBUMP(block, 3, 4, id, 1)},
			[]entry{{txidOnly: &bare}, {raw: parent, bump: 0}, spender(id)})),
			// proof 1^2 * (3+1); chain 2*(2+1); find 1*1.
			Shape{Version: transaction.BEEF_V2, Atomic: true, BUMPs: 1, Leaves: 4, Txs: 3, Inputs: 1, Outputs: 2,
				ProofCost: 4, ChainCost: 6, FindCost: 1}},
		{"heights group by their low 32 bits", beefBytes(true, [][]byte{pair(7, true, 1), pair(7+1<<32, false, 2), pair(8, false, 3)},
			[]entry{{raw: parent, bump: 0}, {raw: other, bump: 2}, {raw: spends, bump: -1}}),
			// proof: one reference at height 7, one at 8, each 1^2 * (1+1).
			Shape{Version: transaction.BEEF_V2, BUMPs: 3, Leaves: 6, Txs: 3, Inputs: 2, Outputs: 3,
				ProofCost: 4, ChainCost: 15, FindCost: 3}},
		{"a path shorter than its offsets need", beefBytes(true, [][]byte{bump(9, [][]leaf{{{1 << 10, 2, node(4, 0)}, {1<<10 + 1, 0, node(4, 1)}}})},
			[]entry{{raw: parent, bump: 0}}),
			// proof: one reference to a path that declares 1 level, whose
			// widest offset, 1,025, needs 11: 1^2 * (11+1).
			Shape{Version: transaction.BEEF_V2, BUMPs: 1, Leaves: 2, Txs: 1, Outputs: 1, ProofCost: 12, ChainCost: 1}},
		{"an extended-format transaction", beefBytes(true, nil, []entry{{raw: efTx([]outpoint{{txid: id}, {txid: bare}}, 25, []int{25, 0, 1}), bump: -1}}),
			Shape{Version: transaction.BEEF_V2, Txs: 1, Inputs: 2, Outputs: 3, ChainCost: 3}},
		{"an empty transaction", beefBytes(false, nil, []entry{{raw: emptyTx(1), bump: -1}}),
			Shape{Version: transaction.BEEF_V1, Txs: 1, ChainCost: 1}},
		{"as many BUMPs as are tracked", oneLeafBUMPs(maxTrackedBUMPs),
			Shape{Version: transaction.BEEF_V2, BUMPs: maxTrackedBUMPs, Leaves: maxTrackedBUMPs, Txs: 1, ProofCost: 2, ChainCost: 1}},
		{"one BUMP more prices all as one height of 255 levels", oneLeafBUMPs(maxTrackedBUMPs + 1),
			Shape{Version: transaction.BEEF_V2, BUMPs: maxTrackedBUMPs + 1, Leaves: maxTrackedBUMPs + 1, Txs: 1,
				ProofCost: 256, ChainCost: 1}},
	}
	for _, c := range cases {
		if got := Scan(c.b); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

// TestScanMatchesParser compares Scan's counts with what go-sdk's parser
// holds for the same bytes.
func TestScanMatchesParser(t *testing.T) {
	corpus := legitimate(t)
	corpus["fan-in"] = fanInV1()
	corpus["extended format"] = beefBytes(false, nil, []entry{{raw: efTx([]outpoint{{txid: node(1, 1)}}, 30, []int{1, 2}), bump: -1}})
	corpus["same-block proofs"] = sameBlockFanIn(true, 20)
	corpus["find"] = findShape(30, 40)
	for name, b := range corpus {
		parsed, err := transaction.NewBeefFromBytes(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got Shape
		got.BUMPs, got.Txs = len(parsed.BUMPs), len(parsed.Transactions)
		for _, p := range parsed.BUMPs {
			for _, level := range p.Path {
				got.Leaves += len(level)
			}
		}
		for _, tx := range parsed.Transactions {
			if tx.Transaction != nil {
				got.Inputs += len(tx.Transaction.Inputs)
				got.Outputs += len(tx.Transaction.Outputs)
			}
		}
		s := Scan(b)
		if s.BUMPs != got.BUMPs || s.Leaves != got.Leaves || s.Txs != got.Txs || s.Inputs != got.Inputs || s.Outputs != got.Outputs {
			t.Errorf("%s: Scan %+v, parser holds %+v", name, s, got)
		}
	}
}

// TestCheckLetsMalformedThrough shows Check refuses nothing for being
// malformed, only for what precedes the fault, and that each case is one the
// parser refuses.
func TestCheckLetsMalformedThrough(t *testing.T) {
	fan := fanInV1()
	badIndex := beefBytes(false, [][]byte{proofBUMP(block, 3, 4, node(9, 9), 1)}, []entry{{raw: emptyTx(1), bump: 5}})
	badFormat := append(beefBytes(true, nil, nil)[:5], 1, 3)
	for name, b := range map[string][]byte{
		"cut short":                 fan[:len(fan)/2],
		"BUMP index past the BUMPs": badIndex,
		"unknown V2 format":         badFormat,
		"BUMPs past the bytes":      overclaim(true),
		"transactions past them":    overclaim(false),
		"unknown version":           {9, 9, 9, 9, 0, 0},
		"Atomic with nothing in it": atomicBEEF(node(1, 1), nil),
	} {
		if err := Check(b); err != nil {
			t.Errorf("%s: Check refused a malformed BEEF: %v", name, err)
		}
		if _, _, _, err := transaction.ParseBeef(b); err == nil {
			t.Errorf("%s: the parser accepts it, so it is not malformed", name)
		}
	}
	over := txsShape(Default.Txs + 1)
	if err := Check(over[:len(over)-3]); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a malformed BEEF already over a cap: %v", err)
	}
}

// TestScanDoesNotAllocateFromCounts shows a walk allocates nothing for what a
// BEEF declares, and for the BUMPs it reads only the doubling table: its
// growth allocates under 4 times the bytes of the entries tracked, which stop
// at maxTrackedBUMPs.
func TestScanDoesNotAllocateFromCounts(t *testing.T) {
	for name, build := range map[string]func() []byte{
		"a BUMP count of 2^63-1":        func() []byte { return overclaim(true) },
		"a transaction count of 2^63-1": func() []byte { return overclaim(false) },
		"64 MiB of empty transactions":  func() []byte { return hugeEmptyTxs(64 << 20) },
		"64 MiB of outputs":             func() []byte { return hugeOutputs(64 << 20) },
	} {
		b := build()
		if n := testing.AllocsPerRun(3, func() { Scan(b) }); n != 0 {
			t.Errorf("%s: Scan allocated %v times", name, n)
		}
	}
	for _, n := range []int{100, 10000, maxTrackedBUMPs, 1 << 20} {
		b := oneLeafBUMPs(n)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		Scan(b)
		runtime.ReadMemStats(&after)
		table := int(unsafe.Sizeof(bumpStat{})) * min(n, maxTrackedBUMPs)
		if got := after.TotalAlloc - before.TotalAlloc; got > uint64(4*table) { //nolint:gosec // positive
			t.Errorf("%d BUMPs: Scan allocated %d bytes, over 4 times the %d bytes of the entries tracked", n, got, table)
		}
	}
}

// TestCheckNamesEachLimit sets each cap one below fanInV1's value for it: the
// refusal names that cap, with the value and the cap, and wraps
// ErrTooComplex. Every value exactly at its cap passes.
func TestCheckNamesEachLimit(t *testing.T) {
	exact := Limits{Txs: 4, Inputs: 3, Outputs: 4, BUMPs: 1, Leaves: 4, ProofCost: 36, ChainCost: 28, FindCost: 1}
	b := fanInV1()
	if err := exact.Check(b); err != nil {
		t.Fatalf("every value at its cap: %v", err)
	}
	for _, c := range []struct {
		lower func(*Limits)
		want  string
	}{
		{func(l *Limits) { l.Txs-- }, "transactions 4 over the cap of 3"},
		{func(l *Limits) { l.Inputs-- }, "inputs 3 over the cap of 2"},
		{func(l *Limits) { l.Outputs-- }, "outputs 4 over the cap of 3"},
		{func(l *Limits) { l.BUMPs-- }, "BUMPs 1 over the cap of 0"},
		{func(l *Limits) { l.Leaves-- }, "leaves 4 over the cap of 3"},
		{func(l *Limits) { l.ProofCost-- }, "proof cost 36 over the cap of 35"},
		{func(l *Limits) { l.ChainCost-- }, "chain cost 28 over the cap of 27"},
		{func(l *Limits) { l.FindCost-- }, "find cost 1 over the cap of 0"},
		// The walk stops at the first output past the cap, not at the last.
		{func(l *Limits) { l.Outputs = 1 }, "outputs 2 over the cap of 1"},
	} {
		l := exact
		c.lower(&l)
		err := l.Check(b)
		if !errors.Is(err, ErrTooComplex) || err.Error() != "BEEF too complex: "+c.want {
			t.Errorf("got %v, want %q", err, c.want)
		}
	}
}

func TestZeroLimitsAllowNone(t *testing.T) {
	if err := (Limits{}).Check(beefBytes(false, nil, nil)); err != nil {
		t.Errorf("a BEEF with nothing in it: %v", err)
	}
	if err := (Limits{}).Check(fanInV1()); !errors.Is(err, ErrTooComplex) {
		t.Errorf("zero limits passed a BEEF: %v", err)
	}
}

func TestDefault(t *testing.T) {
	v := reflect.ValueOf(Default)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("Default.%s is zero, which allows none", v.Type().Field(i).Name)
		}
	}
	if Default.BUMPs > maxTrackedBUMPs {
		t.Errorf("Default.BUMPs %d is over maxTrackedBUMPs %d, so costs would be approximate", Default.BUMPs, maxTrackedBUMPs)
	}
	if Code != "ERR_BEEF_TOO_COMPLEX" {
		t.Errorf("Code is %q", Code)
	}
}
