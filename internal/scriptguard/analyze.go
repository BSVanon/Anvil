package scriptguard

import (
	"bytes"
	"context"

	"github.com/bsv-blockchain/go-sdk/script"
)

// The analysis's own budget. Honest scripts stay far inside it: the costliest
// tested, an OrdLock purchase, takes 2,077 steps (TestCheckPassesHonestScripts).
const (
	// maxPaths caps the paths followed at once. Each unknown OP_IF still
	// open adds at most one, so this is a nesting of 31 undecided branches.
	maxPaths = 32

	// maxWork caps the analysis's steps: one per instruction and path, plus
	// moveWork, joinWork or cloneWork per stack element moved, joined or
	// copied. 64,000,000 steps took at most about 90 ms (see the weights).
	maxWork = 64_000_000

	// The weights of element steps, from TestCheckWorstCaseCost's shapes at
	// the budget: 24,000 undecided OP_IFDUPs (7,980,000 elements joined, 11
	// ns each) took 86-91 ms; 13,000 undecided OP_IFs over 10,001 elements
	// (2,660,000 copied and as many joined, 18 ns the pair) 46-48 ms; and
	// 12,000 OP_ROLLs of 24,000 elements (64,000,000 moved, 0.4 ns each)
	// 23-26 ms.
	moveWork  = 1
	joinWork  = 8
	cloneWork = 8

	// maxLive caps the stack elements all paths hold at once, which bounds
	// the analysis's memory: an element bound takes 40 bytes, so 500,000
	// take 20 MB (the worst shapes grew the heap by at most 32 MB,
	// TestMeasureCheckMemory). One path holds at most the 150,000 elements
	// that 50,000 instructions can push (three for an OP_3DUP), so the cap
	// only stops the copies that undecided branches make of deep stacks.
	maxLive = 500_000

	// ctxEvery is how many steps pass between context checks: 4,096 take
	// about 0.5 ms at most (50,000 one-step instructions took 2.7-6.1 ms,
	// TestCheckWorstCaseCost), plus at most one copy or join of a stack.
	ctxEvery = 1 << 12
)

// path is one way through a script that the analysis follows.
type path struct {
	d, a astack
	// ff is the index in the conditional stack of the path's first false
	// entry, -1 while the path executes. Two paths with the same ff execute
	// the same instructions until the end of the script, so they merge.
	ff int
	// code is the index of the first instruction of the path's scriptCode,
	// one past its last executed OP_CODESEPARATOR.
	code int
}

// analyzer follows a spend's unlocking script then its locking script the
// way the engine executes them after Genesis, with every stack element
// replaced by a bound (see elem), refusing the first guarded opcode whose
// operands the bounds do not keep under its cap.
type analyzer struct {
	ctx       context.Context
	chronicle bool   // the spent output was created after Chronicle
	forkID    bool   // SCRIPT_ENABLE_SIGHASH_FORKID
	numLen    int64  // the era's longest script number
	ver       []byte // the transaction's version as OP_VER pushes it
	progs     [2]*prog
	work      int64
	next      int64 // the step count at which the context is checked next
	// observe, when set, sees the data stack bound of the executing path
	// before each instruction it executes.
	observe func(si, k int, d *astack)
}

// run follows the unlocking script from an empty stack, then the locking
// script from whatever the unlocking script may leave.
func (a *analyzer) run() error {
	start := astack{}
	for si := range a.progs {
		end, err := a.runScript(si, start)
		if err != nil || !end.any {
			return err
		}
		start = end.s
	}
	return nil
}

// ends bounds the data stacks a script may end with, joined as each comes,
// so that however many paths end it holds one stack.
type ends struct {
	s   astack
	any bool // whether any path has ended
}

// add joins the data stack d of a path that ends into e.
func (a *analyzer) add(e *ends, d astack) {
	if !e.any {
		e.s, e.any = d, true
		return
	}
	a.work += joinWork * int64(len(e.s.el)+len(d.el))
	e.s.join(&d)
}

// liveElems counts the stack elements the paths in live and e hold.
func liveElems(live []*path, e *ends) int {
	n := len(e.s.el)
	for _, q := range live {
		n += len(q.d.el) + len(q.a.el)
	}
	return n
}

// tick counts one step and checks the budget and, now and then, ctx.
func (a *analyzer) tick() error {
	a.work++
	if a.work > maxWork {
		return refuse("script analysis", "over its %d-step budget", maxWork)
	}
	if a.work >= a.next {
		a.next = a.work + ctxEvery
		if err := a.ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// runScript follows script si from the data stack start and returns a bound
// on the data stacks it may end with.
func (a *analyzer) runScript(si int, start astack) (ends, error) {
	p := a.progs[si]
	live := []*path{{d: start, ff: -1}}
	var elseSeen []bool // whether each open conditional has had its OP_ELSE
	var end ends
	for k := range p.ins {
		in := &p.ins[k]
		if len(live) == 0 {
			break
		}
		for range live {
			if err := a.tick(); err != nil {
				return ends{}, err
			}
		}
		depth := len(elseSeen)
		switch {
		case in.bad:
			live = nil // fails when reached, executing or not
		case in.op == script.OpIF || in.op == script.OpNOTIF ||
			in.op == script.OpVERIF || in.op == script.OpVERNOTIF:
			if (in.op == script.OpVERIF || in.op == script.OpVERNOTIF) && !a.chronicle {
				live = a.dropExecuting(live) // fails executing, else a NOP
				continue
			}
			next, err := a.branch(si, k, in.op, live, depth, liveElems(live, &end))
			if err != nil {
				return ends{}, err
			}
			live = next
			elseSeen = append(elseSeen, false)
		case in.op == script.OpELSE:
			if depth == 0 || elseSeen[depth-1] {
				live = nil // unbalanced, or a second OP_ELSE: fails
				continue
			}
			elseSeen[depth-1] = true
			for _, q := range live {
				switch q.ff {
				case -1:
					q.ff = depth - 1
				case depth - 1:
					q.ff = -1
				}
			}
		case in.op == script.OpENDIF:
			if depth == 0 {
				live = nil
				continue
			}
			elseSeen = elseSeen[:depth-1]
			live = a.merge(live, depth-1)
		default:
			q := executing(live)
			if q == nil {
				continue
			}
			if a.observe != nil {
				a.observe(si, k, &q.d)
			}
			out, err := a.step(q, si, k, in)
			if err != nil {
				return ends{}, err
			}
			if out == exit {
				a.add(&end, q.d)
			}
			if out != cont {
				live = a.dropExecuting(live)
			}
		}
	}
	if len(elseSeen) == 0 {
		for _, q := range live {
			a.add(&end, q.d)
		}
	}
	return end, nil
}

// branch applies an OP_IF, OP_NOTIF or (Chronicle) OP_VERIF/OP_VERNOTIF at
// conditional depth depth: the executing path pops its condition and goes
// on into the branch, skips it, or, when the analysis cannot tell, both;
// every other path just opens a false entry. held is how many stack
// elements the paths hold before it.
func (a *analyzer) branch(si, k int, op byte, live []*path, depth, held int) ([]*path, error) {
	var next []*path
	for _, q := range live {
		if q.ff >= 0 {
			next = append(next, q)
			continue
		}
		if a.observe != nil {
			a.observe(si, k, &q.d)
		}
		c, ok := q.d.pop()
		if !ok {
			continue
		}
		switch a.truth(op, c) {
		case 1:
			next = append(next, q)
		case 0:
			q.ff = depth
			next = append(next, q)
		default:
			n := len(q.d.el) + len(q.a.el)
			if held+n > maxLive {
				return nil, refuse("OP_IF", "paths holding more than %d stack elements at once", maxLive)
			}
			a.work += cloneWork * int64(n)
			f := &path{d: q.d.clone(), a: q.a.clone(), ff: depth, code: q.code}
			next = append(next, q, f)
		}
	}
	if len(next) > maxPaths {
		return nil, refuse("OP_IF", "more than %d conditional paths at once", maxPaths)
	}
	return next, nil
}

// truth is a conditional's outcome for the popped element c: 1 enters the
// branch, 0 skips it, -1 when the analysis cannot tell.
func (a *analyzer) truth(op byte, c elem) int {
	var t bool
	switch {
	case (op == script.OpVERIF || op == script.OpVERNOTIF) && c.known:
		t = bytes.Equal(c.v, a.ver)
	case op == script.OpVERIF || op == script.OpVERNOTIF:
		if c.n >= int64(len(a.ver)) {
			return -1
		}
		t = false // shorter than the version, so never equal to it
	case c.known:
		t = asBool(c.v)
	default:
		return -1
	}
	if op == script.OpNOTIF || op == script.OpVERNOTIF {
		t = !t
	}
	if t {
		return 1
	}
	return 0
}

// merge applies OP_ENDIF closing entry depth: a path whose first false
// entry it was executes again, and executing paths join into one.
func (a *analyzer) merge(live []*path, depth int) []*path {
	var exec *path
	next := live[:0]
	for _, q := range live {
		if q.ff == depth {
			q.ff = -1
		}
		switch {
		case q.ff != -1:
			next = append(next, q)
		case exec == nil:
			exec = q
			next = append(next, q)
		default:
			a.work += joinWork * int64(len(exec.d.el)+len(exec.a.el)+len(q.d.el)+len(q.a.el))
			exec.d.join(&q.d)
			exec.a.join(&q.a)
			exec.code = min(exec.code, q.code)
		}
	}
	return next
}

// executing returns the path that executes, if any; there is at most one.
func executing(live []*path) *path {
	for _, q := range live {
		if q.ff == -1 {
			return q
		}
	}
	return nil
}

// dropExecuting removes the executing path, which has failed or ended.
func (a *analyzer) dropExecuting(live []*path) []*path {
	next := live[:0]
	for _, q := range live {
		if q.ff != -1 {
			next = append(next, q)
		}
	}
	return next
}
