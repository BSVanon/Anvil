package scriptguard

import (
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
)

// The opcodes whose effect on the stack depends on an operand's value.

// split applies OP_SPLIT: with a known position p, the left part is p bytes
// and the right part at most the rest; otherwise each is at most the whole.
func split(s *astack) (outcome, error) {
	args, ok := take(s, 2)
	if !ok {
		return fail, nil
	}
	x := args[0]
	if p, ok := num(args[1]); ok {
		if p.Sign() < 0 || !p.IsInt64() || p.Int64() > x.n {
			return fail, nil
		}
		n := p.Int64()
		if x.known {
			s.push(exact(x.v[:n]))
			s.push(exact(x.v[n:]))
		} else {
			s.push(sized(n))
			s.push(sized(x.n - n))
		}
		return cont, nil
	}
	s.push(sized(x.n))
	s.push(sized(x.n))
	return cont, nil
}

// pickRoll applies OP_PICK or OP_ROLL. An unknown index may name any
// element, so the stack collapses to a bound on every element.
func (a *analyzer) pickRoll(s *astack, op byte) (outcome, error) {
	ie, ok := s.pop()
	if !ok {
		return fail, nil
	}
	if v, ok := num(ie); ok {
		i := (&interpreter.ScriptNumber{Val: v}).Int32()
		if i < 0 {
			return fail, nil
		}
		if op == script.OpROLL {
			a.work += moveWork * int64(min(int(i), len(s.el))) // the elements it moves
			if !s.roll(int(i)) {
				return fail, nil
			}
			return cont, nil
		}
		x, ok := s.peek(int(i))
		if !ok {
			return fail, nil
		}
		s.push(x)
		return cont, nil
	}
	if s.depth() == 0 {
		return fail, nil
	}
	a.work += moveWork * int64(len(s.el))
	s.collapse()
	if op == script.OpROLL {
		s.rest--
	}
	s.push(sized(s.restN))
	return cont, nil
}

// multisigPops applies OP_CHECKMULTISIG(VERIFY)'s pops: with known counts
// n and m, exactly n+m+3 elements; otherwise at least 3 (n more when n is
// known) out of a collapsed stack.
func (a *analyzer) multisigPops(s *astack, op byte) (outcome, error) {
	ne, _ := s.peek(0)
	n, nKnown, bad := count(ne)
	if bad {
		return fail, nil
	}
	popped := int64(3)
	if nKnown {
		popped += n
		if n > int64(s.depth())-2 {
			return fail, nil
		}
		me, _ := s.peek(int(n) + 1)
		if m, mKnown, mBad := count(me); mBad {
			return fail, nil
		} else if mKnown {
			// Checked before popping, so a count the stack cannot hold
			// costs nothing: the engine needs m <= n and more than m items.
			if m > n || m > int64(s.depth())-3-n {
				return fail, nil
			}
			if _, ok := take(s, int(n+m+3)); !ok {
				return fail, nil
			}
			popped = -1
		}
	}
	if popped >= 0 {
		if int64(s.depth()) < popped {
			return fail, nil
		}
		a.work += moveWork * int64(len(s.el))
		s.collapse()
		s.rest -= int(popped)
	}
	if op == script.OpCHECKMULTISIG {
		s.push(boolElem())
	}
	return cont, nil
}
