package scriptguard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
)

// rng is a xorshift generator, so a failure names a reproducible seed.
type rng struct{ x uint64 }

func (r *rng) next() uint64 {
	r.x ^= r.x << 13
	r.x ^= r.x >> 7
	r.x ^= r.x << 17
	return r.x
}

func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

func (r *rng) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.next())
	}
	return b
}

// push returns one random push: mostly small numbers, which serve as
// indices, counts, sizes and conditions. Nine zero bytes are false, but too
// long for the analysis to keep, so a branch on them goes the way the
// analysis follows less often.
func (r *rng) push() []byte {
	switch r.intn(5) {
	case 0, 1:
		return []byte{[]byte{script.Op0, script.Op1, script.Op2, script.Op3, script.Op4}[r.intn(5)]}
	case 2:
		return dataPush(r.bytes(1 + r.intn(12)))
	default:
		return [][]byte{{script.Op1NEGATE}, {script.Op16}, dataPush([]byte{1, 0, 0, 0}),
			dataPush([]byte{2, 0, 0, 0}), dataPush([]byte{0x80}), dataPush([]byte{0, 0}), dataPush([]byte{0x41}),
			{script.OpPUSHDATA1, 2, 7, 0}, {script.OpPUSHDATA2, 1, 0, 9}, {script.OpPUSHDATA4, 0, 0, 0, 0},
			dataPush(make([]byte, 9))}[r.intn(11)]
	}
}

// piece returns one random instruction or short idiom, at conditional
// nesting depth.
func (r *rng) piece(depth int) []byte {
	switch r.intn(14) {
	case 0, 1, 2:
		return r.push()
	case 3:
		return []byte{[]byte{script.OpIF, script.OpNOTIF, script.OpELSE, script.OpENDIF, script.OpVERIF, script.OpVERNOTIF}[r.intn(6)]}
	case 4:
		return append(r.push(), []byte{script.OpPICK, script.OpROLL}[r.intn(2)])
	case 5, 6:
		return []byte{[]byte{script.OpDUP, script.OpSWAP, script.OpROT, script.OpOVER, script.OpCAT, script.OpSPLIT,
			script.OpSIZE, script.OpEQUAL, script.OpADD, script.OpSUB, script.OpTOALTSTACK, script.OpFROMALTSTACK,
			script.OpNUM2BIN, script.OpBIN2NUM, script.OpLEFT, script.OpSUBSTR, script.OpLSHIFTNUM, script.OpRETURN}[r.intn(18)]}
	case 7:
		if depth < 3 {
			b := append(r.push(), []byte{script.OpIF, script.OpNOTIF, script.OpVERIF}[r.intn(3)])
			b = append(b, r.pieces(depth+1, 5)...)
			if r.intn(2) == 0 {
				b = append(append(b, script.OpELSE), r.pieces(depth+1, 5)...)
			}
			return append(b, script.OpENDIF)
		}
		return r.push()
	default:
		op := script.OpNOP + byte(r.intn(int(script.OpNOP10-script.OpNOP)+1))
		if r.intn(30) == 0 {
			op = []byte{script.OpRESERVED, script.OpRESERVED1, 0xba, 0xff}[r.intn(4)]
		}
		return []byte{op}
	}
}

func (r *rng) pieces(depth, max int) []byte {
	var s []byte
	for n := r.intn(max + 1); n > 0; n-- {
		s = append(s, r.piece(depth)...)
	}
	return s
}

// lock returns a random locking script: a few pushes, then anything.
func (r *rng) lock() []byte {
	var s []byte
	for n := 2 + r.intn(5); n > 0; n-- {
		s = append(s, r.push()...)
	}
	s = append(s, r.pieces(0, 40)...)
	if r.intn(40) == 0 {
		s = append(s, script.OpPUSHDATA1) // an undecodable tail
	}
	return s
}

// nopDebugger implements interpreter.Debugger doing nothing.
type nopDebugger struct{}

func (nopDebugger) BeforeExecute(*interpreter.State)           {}
func (nopDebugger) AfterExecute(*interpreter.State)            {}
func (nopDebugger) BeforeStep(*interpreter.State)              {}
func (nopDebugger) AfterStep(*interpreter.State)               {}
func (nopDebugger) BeforeExecuteOpcode(*interpreter.State)     {}
func (nopDebugger) AfterExecuteOpcode(*interpreter.State)      {}
func (nopDebugger) BeforeScriptChange(*interpreter.State)      {}
func (nopDebugger) AfterScriptChange(*interpreter.State)       {}
func (nopDebugger) AfterSuccess(*interpreter.State)            {}
func (nopDebugger) AfterError(*interpreter.State, error)       {}
func (nopDebugger) BeforeStackPush(*interpreter.State, []byte) {}
func (nopDebugger) AfterStackPush(*interpreter.State, []byte)  {}
func (nopDebugger) BeforeStackPop(*interpreter.State)          {}
func (nopDebugger) AfterStackPop(*interpreter.State, []byte)   {}

// record is what the engine shows before executing one instruction.
type record struct {
	si, k int
	exec  bool
	sizes []int    // the data stack's element lengths, bottom first
	vals  [][]byte // each element's bytes when at most knownMax long
}

// recorder keeps a record for every instruction the engine reaches.
type recorder struct {
	nopDebugger
	recs []record
}

// BeforeExecuteOpcode records whether the instruction can change the data
// stack: after an OP_RETURN inside a branch only another OP_RETURN runs, and
// it changes nothing, so the analysis keeps the stack as it was at the first.
func (r *recorder) BeforeExecuteOpcode(s *interpreter.State) {
	exec := !s.Genesis.EarlyReturn
	for _, c := range s.CondStack {
		exec = exec && c == 1 // opCondTrue
	}
	rc := record{si: s.ScriptIdx, k: s.OpcodeIdx, exec: exec}
	for _, e := range s.DataStack {
		rc.sizes = append(rc.sizes, len(e))
		if len(e) > knownMax {
			e = nil
		}
		rc.vals = append(rc.vals, e)
	}
	r.recs = append(r.recs, rc)
}

// observed reports whether the analysis looks at the stack before op: every
// instruction but OP_ELSE, OP_ENDIF and an undecodable tail, and OP_VERIF
// and OP_VERNOTIF only after Chronicle (before it they fail executing).
func observed(in instr, chronicle bool) bool {
	switch {
	case in.bad, in.op == script.OpELSE, in.op == script.OpENDIF:
		return false
	case in.op == script.OpVERIF || in.op == script.OpVERNOTIF:
		return chronicle
	}
	return true
}

// TestAnalysisBoundsTheEngine runs random scripts through both the engine
// and the analysis, and checks that every instruction the engine executes
// is one the analysis follows, with a stack the analysis's bound covers:
// no deeper, no element longer, and every element it calls known equal.
func TestAnalysisBoundsTheEngine(t *testing.T) {
	runs := 4000
	if v, err := strconv.Atoi(os.Getenv("SCRIPTGUARD_SOUND_RUNS")); err == nil {
		runs = v
	}
	stats := map[string]int{}
	for _, flags := range []scriptflag.Flag{afterChronicle, afterGenesis} {
		for seed := uint64(1); seed <= uint64(runs); seed++ {
			r := &rng{x: seed*0x9e3779b97f4a7c15 + 1}
			var unlock []byte
			for n := r.intn(4); n > 0; n-- {
				unlock = append(unlock, r.push()...)
			}
			version := uint32(1)
			if r.intn(4) == 0 {
				unlock, version = r.pieces(0, 8), 2 // more than pushes: allowed after Chronicle from version 2
			}
			s := lockSpend(r.lock(), unlock)
			s.tx.Version = version
			soundOnce(t, seed, s, flags, stats)
		}
	}
	t.Logf("%v", stats)
	if stats["compared"] < 10*runs {
		t.Fatalf("only %d instructions compared", stats["compared"])
	}
}

func soundOnce(t *testing.T, seed uint64, s spend, flags scriptflag.Flag, stats map[string]int) {
	rec := &recorder{}
	engineErr := interpreter.NewEngine().Execute(interpreter.WithTx(s.tx, s.vin, s.prevout),
		interpreter.WithFlags(flags), interpreter.WithDebugger(rec), interpreter.WithMaxStackMemory(1<<20))
	a := newAnalyzer(context.Background(), s.tx, s.vin, s.prevout, flags)
	snaps := map[[2]int]astack{}
	a.observe = func(si, k int, d *astack) { snaps[[2]int{si, k}] = d.clone() }
	if err := a.run(); err != nil {
		if !errors.Is(err, ErrTooCostly) || bytes.Contains([]byte(err.Error()), []byte("not modelled")) {
			t.Fatalf("seed %d: analysis error %v", seed, err)
		}
		stats["refused: "+err.Error()[len(ErrTooCostly.Error()):]]++
		return
	}
	if engineErr == nil {
		stats["engine passed"]++
	}
	for _, rc := range rec.recs {
		in := a.progs[rc.si].ins[rc.k]
		if !rc.exec || !observed(in, a.chronicle) {
			continue
		}
		b, ok := snaps[[2]int{rc.si, rc.k}]
		if !ok {
			t.Fatalf("seed %d: the engine executes script %d instruction %d (0x%02x) but the analysis does not follow it",
				seed, rc.si, rc.k, in.op)
		}
		if len(rc.sizes) > b.depth() {
			t.Fatalf("seed %d: script %d instruction %d: stack depth %d over the bound %d", seed, rc.si, rc.k, len(rc.sizes), b.depth())
		}
		for i := 0; i < len(rc.sizes); i++ {
			j := len(rc.sizes) - 1 - i
			e, _ := b.peek(i)
			if int64(rc.sizes[j]) > e.n || (e.known && !bytes.Equal(rc.vals[j], e.v)) {
				t.Fatalf("seed %d: script %d instruction %d (0x%02x): element %d from the top is %d bytes %x, bound %+v",
					seed, rc.si, rc.k, in.op, i, rc.sizes[j], rc.vals[j], e)
			}
		}
		stats["compared"]++
	}
}
