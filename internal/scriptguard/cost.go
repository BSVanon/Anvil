package scriptguard

import (
	"fmt"
	"math/big"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
)

// The per-opcode caps. Every other opcode family costs at most about 130 ms
// on the largest operands the engine's default 100,000,000-byte stack
// memory limit admits (go-sdk v1.7.7, amd64, median of 3 runs, over several
// runs: OP_LSHIFT and OP_RSHIFT on 99 MB 119-129 ms, SHA256/HASH256/HASH160
// /SHA1 on 99 MB 37-39 ms, a number opcode on one or two 32,000,000-byte
// numbers at most 75 ms, OP_INVERT on 99 MB 41-61 ms, OP_CHECKSIG over a 32
// MiB scriptCode 34-43 ms, every other family at most 41 ms); see
// measure_test.go.
const (
	// maxArithOperand caps each operand of OP_MUL, OP_DIV and OP_MOD, whose
	// cost grows faster than their length: a 1 MiB by 1 MiB OP_MUL took
	// 258-262 ms and a 2 MiB by 1 MiB OP_DIV or OP_MOD 510-517 ms, while at
	// 64 KiB OP_MUL took 3.5-3.8 ms and a 128 KiB by 64 KiB OP_DIV 6.9 ms.
	maxArithOperand = 64 << 10

	// maxRipemdInput caps the input of OP_RIPEMD160, the slowest hash:
	// 240-242 ms on 99 MB, 81-82 ms on 32 MiB.
	maxRipemdInput = 32 << 20

	// maxNum2binInput caps the number OP_NUM2BIN reads, which it converts
	// to and from a big integer: 136-179 ms on 99 MB of random bytes, 46-57
	// ms on 32 MiB whatever the output length.
	maxNum2binInput = 32 << 20

	// maxFindDeleteWork caps OP_CHECKMULTISIG's FindAndDelete pre-pass,
	// which walks the whole scriptCode once for each signature before the
	// opcode first checks its context. A pass is charged 32 units an
	// instruction and one a byte, at 0.25 ns a unit (8 ns and 0.25 ns), so
	// the cap of 600,000,000 units is 150 ms. Shapes at the cap took less
	// (TestMeasureFindAndDelete): 363 passes over 50,000 one-byte
	// instructions 81 ms, 35 over one 16 MiB push 46 ms, and 312 over 1 MiB
	// of 75-byte pushes 80 ms.
	maxFindDeleteWork = 600_000_000

	// findDeleteInstr is what one instruction counts in maxFindDeleteWork.
	findDeleteInstr = 32
)

// refuse is Check's refusal: name is the opcode or step that would cost too
// much, and the rest says by what measure.
func refuse(name, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrTooCostly, name, fmt.Sprintf(format, args...))
}

var guardedNames = map[byte]string{
	script.OpMUL: "OP_MUL", script.OpDIV: "OP_DIV", script.OpMOD: "OP_MOD",
	script.OpNUM2BIN: "OP_NUM2BIN", script.OpRIPEMD160: "OP_RIPEMD160",
	script.OpCHECKMULTISIG: "OP_CHECKMULTISIG", script.OpCHECKMULTISIGVERIFY: "OP_CHECKMULTISIGVERIFY",
}

// checkCost refuses a guarded opcode about to execute on path q of script
// si when its operands may make it cost more than its cap. An opcode whose
// operands are surely missing fails before any costly work, so it passes.
func (a *analyzer) checkCost(op byte, q *path, si int) error {
	s := &q.d
	switch op {
	case script.OpMUL, script.OpDIV, script.OpMOD:
		x, ok1 := s.peek(0)
		y, ok2 := s.peek(1)
		if n := max(x.n, y.n); ok1 && ok2 && n > maxArithOperand {
			return refuse(guardedNames[op], "an operand of up to %d bytes, over the %d-byte cap", n, maxArithOperand)
		}
	case script.OpRIPEMD160:
		if x, ok := s.peek(0); ok && x.n > maxRipemdInput {
			return refuse(guardedNames[op], "an input of up to %d bytes, over the %d-byte cap", x.n, maxRipemdInput)
		}
	case script.OpNUM2BIN:
		_, ok1 := s.peek(0)
		if x, ok2 := s.peek(1); ok1 && ok2 && x.n > maxNum2binInput {
			return refuse(guardedNames[op], "a number of up to %d bytes, over the %d-byte cap", x.n, maxNum2binInput)
		}
	case script.OpCHECKMULTISIG, script.OpCHECKMULTISIGVERIFY:
		sigs := a.multisigSigs(s)
		if sigs == 0 {
			return nil
		}
		ins, size := a.scriptCode(si, q.code)
		per := plus(min(ins, sizeCap/findDeleteInstr)*findDeleteInstr, size)
		work := sizeCap
		if per == 0 || sigs <= sizeCap/per {
			work = sigs * per
		}
		if work > maxFindDeleteWork {
			return refuse(guardedNames[op], "FindAndDelete work %d (%d signatures over a scriptCode of %d instructions, %d bytes), over the %d cap",
				work, sigs, ins, size, maxFindDeleteWork)
		}
	}
	return nil
}

// count decodes a known CHECKMULTISIG count the way the engine does, as a
// number of at most 4 bytes; ok is false when it is unknown, bad true when
// decoding surely fails or the count is negative.
func count(e elem) (n int64, ok, bad bool) {
	if !e.known {
		return 0, false, false
	}
	v, err := interpreter.MakeScriptNumber(e.v, 4, false, true)
	if err != nil || v.Val.Sign() < 0 {
		return 0, true, true
	}
	return v.Val.Int64(), true, false
}

// multisigSigs bounds the signatures an OP_CHECKMULTISIG(VERIFY) about to
// execute on s runs FindAndDelete for: the engine pops a key count n, needs
// more than n items left, pops n keys and a signature count m <= n, and
// needs more than m items left, so m <= (depth-3)/2. A known signature
// using SIGHASH_FORKID under SCRIPT_ENABLE_SIGHASH_FORKID skips the pass.
func (a *analyzer) multisigSigs(s *astack) int64 {
	d := int64(s.depth())
	ne, ok := s.peek(0)
	if !ok {
		return 0
	}
	n, known, bad := count(ne)
	if bad || (known && n > d-2) {
		return 0
	}
	if !known {
		return max((d-3)/2, 0)
	}
	me, _ := s.peek(int(n) + 1)
	m, mKnown, mBad := count(me)
	if mBad || (mKnown && (m > n || m > d-3-n)) {
		return 0
	}
	if !mKnown {
		return max(min(n, d-3-n), 0)
	}
	sigs := m
	for i := int64(0); i < m && a.forkID; i++ {
		if e, _ := s.peek(int(n + 2 + i)); e.known && len(e.v) > 0 && sighash.Flag(e.v[len(e.v)-1]).Has(sighash.ForkID) {
			sigs--
		}
	}
	return sigs
}

// scriptCode bounds the instructions and bytes of the scriptCode a
// signature opcode of script si hashes when its last OP_CODESEPARATOR was
// before instruction code: the rest of that script and, inside the
// unlocking script (Chronicle), the whole locking script after it, which the
// engine decodes again from the unlocking script's undecodable tail when it
// has one, so that each of those bytes may then be an instruction.
func (a *analyzer) scriptCode(si, code int) (ins, size int64) {
	p := a.progs[si]
	code = min(code, len(p.ins))
	ins, size = int64(len(p.ins)-code), p.tail[code]
	if si == 0 {
		lock := a.progs[1]
		size += lock.tail[0]
		if p.bad {
			ins += lock.tail[0] + p.tail[len(p.ins)-1]
		} else {
			ins += int64(len(lock.ins))
		}
	}
	return ins, size
}

// numBytes is the length of the shortest script number encoding of v >= 0.
func numBytes(v int64) int64 {
	return int64(len((&interpreter.ScriptNumber{Val: big.NewInt(v), AfterGenesis: true}).Bytes()))
}
