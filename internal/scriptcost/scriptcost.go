// Package scriptcost counts, without allocating, what go-sdk v1.7.7 will build
// when it parses a script, so a caller can price untrusted scripts before
// anything parses them.
//
// go-sdk parses a script into one value per instruction, and an instruction
// can be one byte. Its interpreter's parse holds some 128 to 148 bytes an
// instruction while the script runs (5.8 million one-byte instructions held
// 712 MiB on amd64), and script.Chunks 56 bytes a chunk (1.5 million chunks
// held 79.7 MiB), so a script costs many times its own size.
package scriptcost

import (
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/script"
)

// Instructions counts the instructions the interpreter parses s into, up to
// limit+1, and reports whether one of them is outside copyFree. It reads s as
// the interpreter's node-exact parse does: an OP_RETURN does not end it, and a
// truncated push is one last instruction.
func Instructions(s []byte, limit int) (n int, copies bool) {
	for i := 0; i < len(s) && n <= limit; n++ {
		op := s[i]
		size, ok := pushSize(s, i)
		if !ok {
			return n + 1, copies
		}
		if !copyFree[op] {
			copies = true
		}
		i += size
	}
	return n, copies
}

// EndsMalformed reports whether s, read the way the interpreter's node-exact
// parse reads it (see Instructions), ends in an undecodable instruction: a
// push whose length field or data runs past the end of s. This is the same
// condition go-sdk's unexported isMalformed() flags on the last element of a
// parseNodeExact result, so a true here means the interpreter would make a
// signature opcode's subScriptForChecksig re-decode this script joined with
// whatever locking script it spends (script/interpreter/thread.go:1135-1140)
// -- the trigger routeguard refuses before any script runs. An OP_RETURN,
// top-level or not, never ends the walk: a malformed tail reachable only past
// one is still found, matching parseNodeExact and unlike Chunks.
func EndsMalformed(s []byte) bool {
	for i := 0; i < len(s); {
		size, ok := pushSize(s, i)
		if !ok {
			return true
		}
		i += size
	}
	return false
}

// Chunks counts the chunks script.Chunks decodes s into, up to limit+1. It
// reads s as script.DecodeScript does: an OP_RETURN outside every conditional
// block is the last chunk, holding the rest of s, and a truncated push ends
// the decoding with an error.
func Chunks(s []byte, limit int) int {
	n, depth := 0, 0
	for i := 0; i < len(s) && n <= limit; n++ {
		switch op := s[i]; op {
		case script.OpIF, script.OpNOTIF, script.OpVERIF, script.OpVERNOTIF:
			depth++
		case script.OpENDIF:
			depth--
		case script.OpRETURN:
			if depth == 0 {
				return n + 1
			}
		}
		size, ok := pushSize(s, i)
		if !ok {
			return n
		}
		i += size
	}
	return n
}

// copyFree marks the opcodes whose execution holds no more than the script's
// own bytes: pushes, flow control, stack moves (which push an element already
// on the stack again without copying it: 98 OP_DUPs of a 1 MB push held 1.0
// MiB), comparisons, sizes, hashes and signature checks. Every other opcode,
// OP_CAT, OP_SPLIT, OP_NUM2BIN, OP_BIN2NUM, the bitwise and arithmetic
// opcodes, the shifts and the opcodes after OP_NOP3, may write a new element
// as large as the interpreter's stack memory limit allows.
var copyFree = func() (set [256]bool) {
	for op := 0; op <= int(script.Op16); op++ {
		set[op] = true // pushes, OP_1NEGATE, OP_RESERVED and the small numbers
	}
	for op := script.OpNOP; op <= script.OpTUCK; op++ {
		set[op] = true // flow control and stack moves
	}
	for _, op := range []byte{script.OpSIZE, script.OpEQUAL, script.OpEQUALVERIFY,
		script.OpRESERVED1, script.OpRESERVED2} {
		set[op] = true
	}
	for op := script.OpRIPEMD160; op <= script.OpNOP3; op++ {
		set[op] = true // hashes, signature checks, OP_NOP1, CLTV, CSV
	}
	for op := int(script.OpNOP10) + 1; op <= 0xff; op++ {
		set[op] = true // undefined: fails when run
	}
	return set
}()

// pushSize returns the bytes the instruction at s[i] spans, and false when its
// push runs past the end of s.
func pushSize(s []byte, i int) (int, bool) {
	op, rest := s[i], uint64(len(s)-i-1)
	var head, data uint64
	switch {
	case op >= script.OpDATA1 && op <= script.OpDATA75:
		data = uint64(op)
	case op == script.OpPUSHDATA1:
		head = 1
		if rest >= 1 {
			data = uint64(s[i+1])
		}
	case op == script.OpPUSHDATA2:
		head = 2
		if rest >= 2 {
			data = uint64(binary.LittleEndian.Uint16(s[i+1:]))
		}
	case op == script.OpPUSHDATA4:
		head = 4
		if rest >= 4 {
			data = uint64(binary.LittleEndian.Uint32(s[i+1:]))
		}
	}
	if rest < head || rest-head < data {
		return 0, false
	}
	return int(1 + head + data), true // at most len(s)-i
}
