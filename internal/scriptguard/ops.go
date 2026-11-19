package scriptguard

import (
	"bytes"
	"math/big"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
)

// outcome is what executing one instruction does to a path.
type outcome int

const (
	cont outcome = iota // the path goes on
	fail                // the engine surely fails here
	exit                // the script ends here (a top-level OP_RETURN, or one inside a branch)
)

// perm is a stack opcode that pops k elements and pushes them back as out
// lists them, by index from the deepest popped.
type perm struct {
	k   int
	out []int
}

var perms = map[byte]perm{
	script.OpDROP: {1, nil}, script.Op2DROP: {2, nil},
	script.OpDUP: {1, []int{0, 0}}, script.Op2DUP: {2, []int{0, 1, 0, 1}},
	script.Op3DUP: {3, []int{0, 1, 2, 0, 1, 2}}, script.OpOVER: {2, []int{0, 1, 0}},
	script.Op2OVER: {4, []int{0, 1, 2, 3, 0, 1}}, script.OpNIP: {2, []int{1}},
	script.OpSWAP: {2, []int{1, 0}}, script.Op2SWAP: {4, []int{2, 3, 0, 1}},
	script.OpROT: {3, []int{1, 2, 0}}, script.Op2ROT: {6, []int{2, 3, 4, 5, 0, 1}},
	script.OpTUCK: {2, []int{1, 0, 1}},
}

// take pops k elements and returns them deepest first.
func take(s *astack, k int) ([]elem, bool) {
	out := make([]elem, k)
	for i := k - 1; i >= 0; i-- {
		e, ok := s.pop()
		if !ok {
			return nil, false
		}
		out[i] = e
	}
	return out, true
}

// asBool is the engine's truth of an element: any non-zero byte, except a
// final 0x80 (negative zero).
func asBool(b []byte) bool {
	for i := range b {
		if b[i] != 0 {
			return i != len(b)-1 || b[i] != 0x80
		}
	}
	return false
}

// num decodes a known element as a script number.
func num(e elem) (*big.Int, bool) {
	if !e.known {
		return nil, false
	}
	v, err := interpreter.MakeScriptNumber(e.v, len(e.v), false, true)
	if err != nil {
		return nil, false
	}
	return v.Val, true
}

func numElem(v int64) elem {
	return exact((&interpreter.ScriptNumber{Val: big.NewInt(v), AfterGenesis: true}).Bytes())
}

func boolElem() elem { return sized(1) }

// step applies instruction k of script si, an opcode other than
// OP_IF/OP_NOTIF/OP_VERIF/OP_VERNOTIF/OP_ELSE/OP_ENDIF, to the executing
// path q, refusing it first when its cost may be over its cap.
func (a *analyzer) step(q *path, si, k int, in *instr) (outcome, error) {
	s := &q.d
	op := in.op
	switch {
	case op == script.Op0:
		s.push(exact([]byte{}))
		return cont, nil
	case op <= script.OpPUSHDATA4:
		s.push(exact(in.data))
		return cont, nil
	case op == script.Op1NEGATE:
		s.push(exact([]byte{0x81}))
		return cont, nil
	case op >= script.Op1 && op <= script.Op16:
		s.push(exact([]byte{op - script.Op1 + 1}))
		return cont, nil
	}
	if guarded(op) {
		if err := a.checkCost(op, q, si); err != nil {
			return fail, err
		}
	}
	if p, ok := perms[op]; ok {
		args, ok := take(s, p.k)
		if !ok {
			return fail, nil
		}
		for _, i := range p.out {
			s.push(args[i])
		}
		return cont, nil
	}
	if out, ok := a.stepChronicle(s, op); ok {
		return out, nil
	}
	return a.stepOther(q, s, k, op)
}

// unop pops one element and pushes f of it.
func unop(s *astack, f func(x elem) elem) (outcome, error) {
	x, ok := s.pop()
	if !ok {
		return fail, nil
	}
	s.push(f(x))
	return cont, nil
}

// binop pops two elements, x the deeper, and pushes f of them.
func binop(s *astack, f func(x, y elem) elem) (outcome, error) {
	args, ok := take(s, 2)
	if !ok {
		return fail, nil
	}
	s.push(f(args[0], args[1]))
	return cont, nil
}

// stepChronicle handles the opcodes whose meaning Chronicle changed: OP_2MUL
// and OP_2DIV, disabled before it (failing then, so their Chronicle effect
// over-approximates), and OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_LSHIFTNUM and
// OP_RSHIFTNUM, which were OP_NOP4 to OP_NOP8 for an output created before
// it. ok is false for any other opcode.
func (a *analyzer) stepChronicle(s *astack, op byte) (outcome, bool) {
	var out outcome
	switch op {
	case script.Op2MUL:
		out, _ = unop(s, func(x elem) elem { return sized(plus(x.n, 1)) })
	case script.Op2DIV:
		out, _ = unop(s, func(x elem) elem { return sized(x.n) })
	case script.OpSUBSTR, script.OpLEFT, script.OpRIGHT, script.OpLSHIFTNUM, script.OpRSHIFTNUM:
		if !a.chronicle {
			return cont, true
		}
		k := 2
		if op == script.OpSUBSTR {
			k = 3
		}
		args, ok := take(s, k)
		if !ok {
			return fail, true
		}
		r := sized(args[0].n) // a slice of the data, or a right-shifted number
		if op == script.OpLSHIFTNUM {
			r = sized(a.numLen) // pushArithResult caps the result
		}
		s.push(r)
	default:
		return cont, false
	}
	return out, true
}

// stepOther handles every remaining opcode.
func (a *analyzer) stepOther(q *path, s *astack, k int, op byte) (outcome, error) {
	switch op {
	case script.OpNOP, script.OpNOP1, script.OpNOP9, script.OpNOP10,
		script.OpCHECKLOCKTIMEVERIFY, script.OpCHECKSEQUENCEVERIFY:
		return cont, nil // none changes the stacks; any that fails only ends the path sooner
	case script.OpVER:
		s.push(exact(a.ver)) // fails before Chronicle, so pushing over-approximates
		return cont, nil
	case script.OpRETURN:
		return exit, nil
	case script.OpVERIFY:
		x, ok := s.pop()
		if !ok || (x.known && !asBool(x.v)) {
			return fail, nil
		}
		return cont, nil
	case script.OpTOALTSTACK, script.OpFROMALTSTACK:
		from, to := s, &q.a
		if op == script.OpFROMALTSTACK {
			from, to = &q.a, s
		}
		x, ok := from.pop()
		if !ok {
			return fail, nil
		}
		to.push(x)
		return cont, nil
	case script.OpIFDUP:
		x, ok := s.peek(0)
		switch {
		case !ok:
			return fail, nil
		case x.known && asBool(x.v):
			s.push(x)
		case !x.known:
			a.work += joinWork * int64(len(s.el))
			s.dupJoin(x)
		}
		return cont, nil
	case script.OpDEPTH:
		if s.rest == 0 {
			s.push(numElem(int64(len(s.el))))
		} else {
			s.push(sized(numBytes(int64(s.depth()))))
		}
		return cont, nil
	case script.OpPICK, script.OpROLL:
		return a.pickRoll(s, op)
	case script.OpCAT:
		return binop(s, func(x, y elem) elem {
			if x.known && y.known {
				return exact(append(append([]byte{}, x.v...), y.v...))
			}
			return sized(plus(x.n, y.n))
		})
	case script.OpSPLIT:
		return split(s)
	case script.OpNUM2BIN:
		return binop(s, func(x, size elem) elem {
			if v, ok := num(size); ok && v.Sign() >= 0 && v.IsInt64() {
				return sized(v.Int64())
			}
			return sized(sizeCap)
		})
	case script.OpBIN2NUM:
		return unop(s, func(x elem) elem {
			if x.known {
				return exact(interpreter.MinimallyEncode(append([]byte{}, x.v...)))
			}
			return sized(x.n)
		})
	case script.OpSIZE:
		x, ok := s.peek(0)
		if !ok {
			return fail, nil
		}
		if x.known {
			s.push(numElem(int64(len(x.v))))
		} else {
			s.push(sized(numBytes(x.n)))
		}
		return cont, nil
	case script.OpINVERT, script.OpNEGATE, script.OpABS:
		return unop(s, func(x elem) elem { return sized(x.n) })
	case script.Op1ADD, script.Op1SUB:
		return unop(s, func(x elem) elem { return sized(plus(x.n, 1)) })
	case script.OpNOT, script.Op0NOTEQUAL, script.OpSHA1, script.OpRIPEMD160, script.OpHASH160,
		script.OpSHA256, script.OpHASH256:
		return unop(s, func(elem) elem { return sized(hashLen[op]) })
	case script.OpAND, script.OpOR, script.OpXOR, script.OpMOD:
		return binop(s, func(x, y elem) elem { return sized(min(x.n, y.n)) })
	case script.OpLSHIFT, script.OpRSHIFT, script.OpDIV:
		return binop(s, func(x, _ elem) elem { return sized(x.n) })
	case script.OpADD, script.OpSUB:
		return binop(s, func(x, y elem) elem { return sized(plus(max(x.n, y.n), 1)) })
	case script.OpMUL:
		return binop(s, func(x, y elem) elem { return sized(min(plus(plus(x.n, y.n), 1), a.numLen)) })
	case script.OpMIN, script.OpMAX:
		return binop(s, func(x, y elem) elem { return sized(max(x.n, y.n)) })
	case script.OpEQUAL:
		return binop(s, func(x, y elem) elem {
			if x.known && y.known {
				if bytes.Equal(x.v, y.v) {
					return exact([]byte{1})
				}
				return exact([]byte{})
			}
			return boolElem()
		})
	case script.OpBOOLAND, script.OpBOOLOR, script.OpNUMEQUAL, script.OpNUMNOTEQUAL, script.OpLESSTHAN,
		script.OpGREATERTHAN, script.OpLESSTHANOREQUAL, script.OpGREATERTHANOREQUAL, script.OpCHECKSIG:
		return binop(s, func(_, _ elem) elem { return boolElem() })
	case script.OpEQUALVERIFY:
		args, ok := take(s, 2)
		if !ok || (args[0].known && args[1].known && !bytes.Equal(args[0].v, args[1].v)) {
			return fail, nil
		}
		return cont, nil
	case script.OpNUMEQUALVERIFY, script.OpCHECKSIGVERIFY:
		if _, ok := take(s, 2); !ok {
			return fail, nil
		}
		return cont, nil
	case script.OpWITHIN:
		if _, ok := take(s, 3); !ok {
			return fail, nil
		}
		s.push(boolElem())
		return cont, nil
	case script.OpCODESEPARATOR:
		q.code = k + 1
		return cont, nil
	case script.OpCHECKMULTISIG, script.OpCHECKMULTISIGVERIFY:
		return a.multisigPops(s, op)
	case script.OpRESERVED, script.OpRESERVED1, script.OpRESERVED2:
		return fail, nil
	}
	if op >= 0xba {
		return fail, nil // OP_UNKNOWN186 and above: invalid when executed
	}
	return fail, refuse("opcode", "0x%02x is not modelled", op)
}

// hashLen is the length of what each fixed-size result opcode pushes.
var hashLen = map[byte]int64{
	script.OpNOT: 1, script.Op0NOTEQUAL: 1,
	script.OpSHA1: 20, script.OpRIPEMD160: 20, script.OpHASH160: 20,
	script.OpSHA256: 32, script.OpHASH256: 32,
}
