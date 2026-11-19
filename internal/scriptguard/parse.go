package scriptguard

import (
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/script"
)

// instr is one instruction of a script, decoded the way go-sdk v1.7.7's
// engine decodes it (its node-exact parse, interpreter/opcodeparser.go
// decodeInstruction and parseNodeExact).
type instr struct {
	data []byte // the pushed bytes; nil for OP_0 and every non-push
	op   byte
	bad  bool // an undecodable push: it and every byte after it, failing when reached
}

// prog is a decoded script.
type prog struct {
	ins []instr
	// tail[k] is the byte length of ins[k:], so tail[0] is the script's.
	tail []int64
	// bad reports that the script ends in an undecodable instruction.
	bad bool
}

// decode splits s into instructions. A push whose length field or data runs
// past the end of s becomes, with every byte after it, one final instruction
// that fails when execution reaches it, as in the engine.
func decode(s []byte) *prog {
	n := instrCount(s)
	p := &prog{ins: make([]instr, 0, n), tail: make([]int64, n+1)}
	for i := 0; i < len(s); {
		p.tail[len(p.ins)] = int64(len(s) - i)
		start, end, ok := decodeAt(s, i)
		if !ok {
			p.ins = append(p.ins, instr{op: s[i], bad: true})
			p.bad = true
			break
		}
		in := instr{op: s[i]}
		if s[i] != script.Op0 && s[i] <= script.OpPUSHDATA4 {
			in.data = s[start:end]
		}
		p.ins = append(p.ins, in)
		i = end
	}
	return p
}

// instrCount is how many instructions decode makes of s, counted first so
// that decode allocates once.
func instrCount(s []byte) int {
	n := 0
	for i := 0; i < len(s); {
		n++
		_, end, ok := decodeAt(s, i)
		if !ok {
			break
		}
		i = end
	}
	return n
}

// decodeAt returns the offsets of the data pushed by the instruction at
// s[i] and of its end, and ok=false when it runs past the end of s.
func decodeAt(s []byte, i int) (start, end int, ok bool) {
	var size uint64
	switch op := s[i]; {
	case op < script.OpPUSHDATA1:
		start, size = i+1, uint64(op)
	case op == script.OpPUSHDATA1:
		if len(s)-(i+1) < 1 {
			return 0, 0, false
		}
		start, size = i+2, uint64(s[i+1])
	case op == script.OpPUSHDATA2:
		if len(s)-(i+1) < 2 {
			return 0, 0, false
		}
		start, size = i+3, uint64(binary.LittleEndian.Uint16(s[i+1:]))
	case op == script.OpPUSHDATA4:
		if len(s)-(i+1) < 4 {
			return 0, 0, false
		}
		start, size = i+5, uint64(binary.LittleEndian.Uint32(s[i+1:]))
	default:
		return i + 1, i + 1, true
	}
	if uint64(len(s)-start) < size {
		return 0, 0, false
	}
	return start, start + int(size), true
}

// guarded reports whether op is one of the opcodes whose cost Check bounds.
func guarded(op byte) bool {
	switch op {
	case script.OpMUL, script.OpDIV, script.OpMOD, script.OpNUM2BIN, script.OpRIPEMD160,
		script.OpCHECKMULTISIG, script.OpCHECKMULTISIGVERIFY:
		return true
	}
	return false
}

// hasGuarded reports whether p has an instruction that is a guarded opcode.
func (p *prog) hasGuarded() bool {
	for _, in := range p.ins {
		if !in.bad && guarded(in.op) {
			return true
		}
	}
	return false
}
