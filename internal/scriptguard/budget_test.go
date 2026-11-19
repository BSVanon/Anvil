package scriptguard

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
)

// unknownTop pushes an element the analysis cannot know: a hash of OP_1.
var unknownTop = ops(script.Op1, script.OpSHA256)

// TestCheckModelsEveryOpcode: every byte value, executed on a stack of small
// known numbers, has a model (none reaches the refusal for an opcode the
// analysis does not know), in both eras after Genesis.
func TestCheckModelsEveryOpcode(t *testing.T) {
	for op := 0; op < 256; op++ {
		lock := ops(script.Op2, script.Op1, script.Op2, script.Op1, script.Op1, script.Op2)
		switch {
		case op >= 1 && op <= 75:
			lock = append(lock, dataPush(make([]byte, op))...)
		case op == int(script.OpPUSHDATA1):
			lock = append(lock, byte(op), 1, 7)
		case op == int(script.OpPUSHDATA2):
			lock = append(lock, byte(op), 1, 0, 7)
		case op == int(script.OpPUSHDATA4):
			lock = append(lock, byte(op), 1, 0, 0, 0, 7)
		default:
			lock = append(lock, byte(op))
		}
		for _, era := range eras[:2] {
			s := lockSpend(lock, nil)
			a := newAnalyzer(context.Background(), s.tx, 0, s.prevout, era.flags)
			if err := a.run(); err != nil {
				t.Errorf("opcode 0x%02x, %s: %v", op, era.name, err)
			}
		}
	}
}

// nestedIfs is d undecided OP_IFs, an OP_MUL of small numbers, and d
// OP_ENDIFs: d+1 paths at once inside.
func nestedIfs(d int) spend {
	var lock []byte
	for i := 0; i < d; i++ {
		lock = append(append(lock, unknownTop...), script.OpIF)
	}
	lock = append(lock, script.Op2, script.Op3, script.OpMUL, script.OpDROP)
	lock = append(lock, repeat(script.OpENDIF, d)...)
	return lockSpend(append(lock, script.Op1), nil)
}

// TestCheckPathCap: up to maxPaths paths at once pass; one more is refused.
func TestCheckPathCap(t *testing.T) {
	if err := check(nestedIfs(maxPaths-1), afterChronicle); err != nil {
		t.Errorf("%d nested undecided branches: Check = %v, want nil", maxPaths-1, err)
	}
	err := check(nestedIfs(maxPaths), afterChronicle)
	if !errors.Is(err, ErrTooCostly) || !strings.Contains(err.Error(), "conditional paths") {
		t.Errorf("%d nested undecided branches: Check = %v, want the path refusal", maxPaths, err)
	}
}

// openIfs is depth OP_1s, then maxPaths-1 undecided OP_IFs left open, so that
// each copies the stack for a new path, then dups OP_DUPs and an OP_MUL.
func openIfs(depth, dups int) spend {
	lock := repeat(script.Op1, depth)
	for i := 0; i < maxPaths-1; i++ {
		lock = append(append(lock, unknownTop...), script.OpIF)
	}
	lock = append(lock, repeat(script.OpDUP, dups)...)
	return lockSpend(append(lock, script.OpMUL), nil)
}

// forks is 10,000 OP_1s and an unknown element, then n undecided OP_IFs on
// copies of it, each copying the 10,001 elements for a new path and joining
// them back at its OP_ENDIF: 240,028 steps each with the weights.
func forks(n int) spend {
	lock := append(repeat(script.Op1, 10_000), unknownTop...)
	for i := 0; i < n; i++ {
		lock = append(lock, script.OpDUP, script.OpIF, script.OpENDIF)
	}
	return lockSpend(append(lock, script.OpMUL), nil)
}

// worstShapes are scripts at about the routeguard's 50,000-instruction cap
// that make the analysis do the most work it can per instruction.
func worstShapes() map[string]spend {
	rolls := repeat(script.Op1, 25_000)
	for i := 0; i < 12_000; i++ {
		rolls = append(rolls, dataPush(le(24_000))...)
		rolls = append(rolls, script.OpROLL)
	}
	ifdups := append(repeat(script.Op1, 25_000), unknownTop...)
	ifdups = append(ifdups, repeat(script.OpIFDUP, 24_000)...)
	return map[string]spend{
		"49,999 OP_1 then OP_MUL":               lockSpend(append(repeat(script.Op1, 49_999), script.OpMUL), nil),
		"12,000 deep OP_ROLLs":                  lockSpend(append(rolls, script.OpMUL), nil),
		"13,000 undecided OP_IFs, 10,000 deep":  forks(13_000),
		"24,000 undecided OP_IFDUPs":            lockSpend(append(ifdups, script.OpMUL), nil),
		"31 open undecided OP_IFs, 15,000 deep": openIfs(15_000, 34_000),
		"31 open undecided OP_IFs, 18,000 deep": openIfs(18_000, 31_000),
		"the reviewer's multisig":               multisigShape(0, 24990, 24990),
	}
}

// TestCheckWorstCaseCost: on each worst shape Check ends, by a verdict or
// its work budget, within maxCheckTime, and each instruction-count shape is
// at the routeguard cap.
func TestCheckWorstCaseCost(t *testing.T) {
	maxCheckTime := 500 * time.Millisecond // generous for a loaded test machine; logged below
	if raceEnabled {
		maxCheckTime *= 4 // see race_on_test.go
	}
	for name, s := range worstShapes() {
		n := len(decode(*s.prevout.LockingScript).ins) + len(decode(*s.tx.Inputs[0].UnlockingScript).ins)
		if n > 50_000 {
			t.Fatalf("%s: %d instructions, over the routeguard cap", name, n)
		}
		var err error
		d := median(3, func() { err = check(s, afterChronicle) })
		if d > maxCheckTime {
			t.Errorf("%s: Check took %v", name, d)
		}
		msg := "nil"
		if err != nil {
			msg = err.Error()
		}
		t.Logf("%-40s %6d instructions, Check %8.2f ms: %s", name, n, float64(d.Microseconds())/1000, msg)
	}
}

// TestCheckLiveCap: copies of the stack for undecided branches pass up to
// maxLive elements held at once (32 paths of 15,000) and are refused past it
// (32 of 18,000).
func TestCheckLiveCap(t *testing.T) {
	if err := check(openIfs(15_000, 34_000), afterChronicle); err != nil {
		t.Errorf("32 paths of 15,000 elements: Check = %v, want nil", err)
	}
	err := check(openIfs(18_000, 31_000), afterChronicle)
	if !errors.Is(err, ErrTooCostly) || !strings.Contains(err.Error(), "stack elements at once") {
		t.Errorf("32 paths of 18,000 elements: Check = %v, want the live element refusal", err)
	}
}

// TestCheckMultisigCountCostsNothing: a known signature count the stack
// cannot hold fails at once, without the analysis allocating for it.
func TestCheckMultisigCountCostsNothing(t *testing.T) {
	s := lockSpend(cat(ops(script.Op1), dataPush(le(10_000_000)), ops(script.Op0, script.OpCHECKMULTISIG)), nil)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := check(s, afterChronicle)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
	if b := after.TotalAlloc - before.TotalAlloc; b > 1<<20 {
		t.Fatalf("Check allocated %d bytes for a signature count of 10,000,000", b)
	}
}

// TestCheckWorkBudget: an analysis over maxWork steps is refused, for each
// shape whose work is per stack element, and the steps add up as the weights
// say: 250 undecided branches over 10,001 elements take 10,003 steps for the
// other instructions and 240,028 for each branch, 60,017,003 in all, and
// pass; 280 would take 67,217,843 and are refused.
func TestCheckWorkBudget(t *testing.T) {
	shapes := worstShapes()
	for _, name := range []string{"12,000 deep OP_ROLLs", "13,000 undecided OP_IFs, 10,000 deep", "24,000 undecided OP_IFDUPs"} {
		err := check(shapes[name], afterChronicle)
		if !errors.Is(err, ErrTooCostly) || !strings.Contains(err.Error(), "script analysis") {
			t.Errorf("%s: Check = %v, want the work budget refusal", name, err)
		}
	}
	s := forks(250)
	a := newAnalyzer(context.Background(), s.tx, 0, s.prevout, afterChronicle)
	if err := a.run(); err != nil || a.work != 60_017_003 {
		t.Errorf("250 undecided branches: %v after %d steps, want nil after 60,017,003", err, a.work)
	}
	if err := check(forks(280), afterChronicle); !errors.Is(err, ErrTooCostly) || !strings.Contains(err.Error(), "script analysis") {
		t.Errorf("280 undecided branches: Check = %v, want the work budget refusal", err)
	}
}

// doneAfter is a context whose Err turns to context.Canceled after n calls.
type doneAfter struct {
	context.Context
	n int
}

func (c *doneAfter) Err() error {
	if c.n--; c.n < 0 {
		return context.Canceled
	}
	return nil
}

// TestCheckStopsWithTheContext: the analysis checks its context as it goes,
// and returns the context's error.
func TestCheckStopsWithTheContext(t *testing.T) {
	s := worstShapes()["49,999 OP_1 then OP_MUL"]
	ctx := &doneAfter{Context: context.Background(), n: 3}
	if err := Check(ctx, s.tx, 0, s.prevout, afterChronicle); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check = %v, want context.Canceled", err)
	}
	if ctx.n > 0 {
		t.Fatal("the context was not checked during the analysis")
	}
}
