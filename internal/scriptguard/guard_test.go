package scriptguard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func ops(b ...byte) []byte { return b }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// numPush pushes an n-byte positive number.
func numPush(n int) []byte { return pushData4(randNum(n, uint64(n)+1)) }

// multisigLock is <code> OP_DROP-free filler, then a multisig with m known
// one-byte signatures and m keys: unlocking OP_0 <0x01 * m>, locking
// [<filler> OP_DROP] <m> <key * m> <m> op.
func multisigLock(filler, m int, op byte) spend {
	var lock []byte
	if filler > 0 {
		lock = append(pushData4(make([]byte, filler)), script.OpDROP)
	}
	lock = append(lock, dataPush(le(m))...)
	for i := 0; i < m; i++ {
		lock = append(lock, dataPush(make([]byte, 33))...)
	}
	lock = append(lock, dataPush(le(m))...)
	lock = append(lock, op)
	unlock := []byte{script.Op0}
	for i := 0; i < m; i++ {
		unlock = append(unlock, script.Op1)
	}
	return lockSpend(lock, unlock)
}

// findDeleteWork is the work Check charges m signatures over lock.
func findDeleteWork(lock []byte, m int) int64 {
	p := decode(lock)
	return int64(m) * (findDeleteInstr*int64(len(p.ins)) + p.tail[0])
}

// TestCheckGuards: each guarded opcode is refused just over its cap and
// passes at it, under both eras after Genesis.
func TestCheckGuards(t *testing.T) {
	over, at := maxArithOperand+1, maxArithOperand
	under := multisigLock(1_000_000, 500, script.OpCHECKMULTISIG)
	overMS := multisigLock(1_000_000, 600, script.OpCHECKMULTISIG)
	cases := []struct {
		name string
		s    spend
		op   string // "" for a pass
	}{
		{"MUL over", lockSpend(cat(numPush(over), ops(script.Op1, script.OpMUL)), nil), "OP_MUL"},
		{"MUL second operand over", lockSpend(cat(ops(script.Op1), numPush(over), ops(script.OpMUL)), nil), "OP_MUL"},
		{"MUL at the cap", lockSpend(cat(numPush(at), numPush(at), ops(script.OpMUL)), nil), ""},
		{"DIV over", lockSpend(cat(numPush(over), ops(script.Op1, script.OpDIV)), nil), "OP_DIV"},
		{"DIV at the cap", lockSpend(cat(numPush(at), numPush(at), ops(script.OpDIV)), nil), ""},
		{"MOD over", lockSpend(cat(numPush(over), ops(script.Op3, script.OpMOD)), nil), "OP_MOD"},
		{"MOD at the cap", lockSpend(cat(numPush(at), numPush(at), ops(script.OpMOD)), nil), ""},
		{"RIPEMD160 over", lockSpend(cat(pushData4(make([]byte, maxRipemdInput+1)), ops(script.OpRIPEMD160)), nil), "OP_RIPEMD160"},
		{"RIPEMD160 at the cap", lockSpend(cat(pushData4(make([]byte, maxRipemdInput)), ops(script.OpRIPEMD160)), nil), ""},
		{"NUM2BIN over", lockSpend(cat(pushData4(make([]byte, maxNum2binInput+1)), dataPush(le(40_000_000)), ops(script.OpNUM2BIN)), nil), "OP_NUM2BIN"},
		{"NUM2BIN at the cap", lockSpend(cat(pushData4(make([]byte, maxNum2binInput)), dataPush(le(40_000_000)), ops(script.OpNUM2BIN)), nil), ""},
		{"NUM2BIN padding", lockSpend(cat(ops(script.Op0), dataPush(le(90_000_000)), ops(script.OpNUM2BIN)), nil), ""},
		{"CHECKMULTISIG under", under, ""},
		{"CHECKMULTISIG over", overMS, "OP_CHECKMULTISIG"},
		{"CHECKMULTISIGVERIFY over", multisigLock(1_000_000, 600, script.OpCHECKMULTISIGVERIFY), "OP_CHECKMULTISIGVERIFY"},
	}
	if w := findDeleteWork(*under.prevout.LockingScript, 500); w > maxFindDeleteWork {
		t.Fatalf("the passing multisig charges %d", w)
	}
	if w := findDeleteWork(*overMS.prevout.LockingScript, 600); w <= maxFindDeleteWork {
		t.Fatalf("the refused multisig charges %d", w)
	}
	for _, c := range cases {
		for _, era := range eras[:2] {
			err := check(c.s, era.flags)
			switch {
			case c.op == "" && err != nil:
				t.Errorf("%s, %s: Check = %v, want nil", c.name, era.name, err)
			case c.op != "" && (!errors.Is(err, ErrTooCostly) || !containsWord(err.Error(), c.op)):
				t.Errorf("%s, %s: Check = %v, want ErrTooCostly at %s", c.name, era.name, err, c.op)
			}
		}
	}
}

// TestCheckMultisigScriptCode: the work counts every signature without
// SIGHASH_FORKID, the scriptCode from the last executed OP_CODESEPARATOR,
// and inside the unlocking script the locking script too.
func TestCheckMultisigScriptCode(t *testing.T) {
	refused := multisigLock(1_000_000, 600, script.OpCHECKMULTISIG)
	err := check(refused, afterChronicle)
	want := fmt.Sprintf("FindAndDelete work %d ", findDeleteWork(*refused.prevout.LockingScript, 600))
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Check = %v, want %q", err, want)
	}

	// OP_CODESEPARATOR after the filler leaves it out of the scriptCode.
	sep := multisigLock(1_000_000, 600, script.OpCHECKMULTISIG)
	lock := *sep.prevout.LockingScript
	lock = cat(lock[:5+1_000_000+1], ops(script.OpCODESEPARATOR), lock[5+1_000_000+1:])
	sep = lockSpend(lock, *sep.tx.Inputs[0].UnlockingScript)
	if err := check(sep, afterChronicle); err != nil {
		t.Errorf("after OP_CODESEPARATOR: Check = %v, want nil", err)
	}

	// Signatures that carry SIGHASH_FORKID (0x41) skip the pass.
	forkID := multisigLock(1_000_000, 600, script.OpCHECKMULTISIG)
	unlock := []byte{script.Op0}
	for i := 0; i < 600; i++ {
		unlock = append(unlock, dataPush([]byte{0x41})...)
	}
	forkID.tx.Inputs[0].UnlockingScript = (*script.Script)(&unlock)
	if err := check(forkID, afterChronicle); err != nil {
		t.Errorf("FORKID signatures: Check = %v, want nil", err)
	}
	if err := check(forkID, afterChronicle&^scriptflag.EnableSighashForkID); !errors.Is(err, ErrTooCostly) {
		t.Errorf("FORKID signatures without SCRIPT_ENABLE_SIGHASH_FORKID: Check = %v, want ErrTooCostly", err)
	}

	// In the unlocking script (Chronicle, version 2) the locking script's
	// bytes are part of the scriptCode.
	var ms []byte
	ms = append(ms, script.Op0)
	for i := 0; i < 600; i++ {
		ms = append(ms, script.Op1)
	}
	ms = append(ms, dataPush(le(600))...)
	for i := 0; i < 600; i++ {
		ms = append(ms, dataPush(make([]byte, 33))...)
	}
	ms = append(ms, dataPush(le(600))...)
	ms = append(ms, script.OpCHECKMULTISIG)
	inUnlock := lockSpend(cat(pushData4(make([]byte, 2_000_000)), ops(script.Op2DROP, script.Op1)), ms)
	inUnlock.tx.Version = 2
	if err := check(inUnlock, afterChronicle); !errors.Is(err, ErrTooCostly) {
		t.Errorf("multisig in the unlocking script: Check = %v, want ErrTooCostly", err)
	}
	if err := check(lockSpend(ops(script.Op2DROP, script.Op1), ms), afterChronicle); err != nil {
		t.Errorf("the same with a short locking script: Check = %v, want nil", err)
	}

	// An undecodable tail on the unlocking script is decoded again with the
	// locking script's bytes after it, so each of those may then be an
	// instruction: 20 signatures over a 1,000,000-byte push pass with the
	// unlocking script ending in OP_NOP (20,045,000 units) and are refused
	// with it ending in a bare OP_PUSHDATA1 (660,048,200).
	ms20 := cat(ops(script.Op0), repeat(script.Op1, 20), dataPush(le(20)))
	for i := 0; i < 20; i++ {
		ms20 = append(ms20, dataPush(make([]byte, 33))...)
	}
	ms20 = cat(ms20, dataPush(le(20)), ops(script.OpCHECKMULTISIG))
	bigLock := cat(pushData4(make([]byte, 1_000_000)), ops(script.OpDROP, script.Op1))
	for tail, want := range map[byte]string{script.OpNOP: "", script.OpPUSHDATA1: "FindAndDelete work 660048200 "} {
		s := lockSpend(bigLock, cat(ms20, ops(tail)))
		s.tx.Version = 2
		if err := check(s, afterChronicle); (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("multisig in an unlocking script ending in 0x%02x: Check = %v, want %q", tail, err, want)
		}
	}

	// An unknown signature count is bounded by the key count and the depth:
	// 600 here, as many as the refused shape above has.
	unknownM := cat(pushData4(make([]byte, 1_000_000)), ops(script.OpDROP), unknownTop)
	for i := 0; i < 600; i++ {
		unknownM = append(unknownM, dataPush(make([]byte, 33))...)
	}
	unknownM = cat(unknownM, dataPush(le(600)), ops(script.OpCHECKMULTISIG))
	if err := check(lockSpend(unknownM, *refused.tx.Inputs[0].UnlockingScript), afterChronicle); !errors.Is(err, ErrTooCostly) {
		t.Errorf("unknown signature count: Check = %v, want ErrTooCostly", err)
	}

	// An unknown key count is bounded by the stack depth.
	unknown := lockSpend(cat(pushData4(make([]byte, 1_000_000)), ops(script.OpDROP),
		repeat(script.Op1, 2000), ops(script.Op1, script.OpSHA256, script.OpCHECKMULTISIG)), nil)
	if err := check(unknown, afterChronicle); !errors.Is(err, ErrTooCostly) {
		t.Errorf("unknown key count: Check = %v, want ErrTooCostly", err)
	}
}

func repeat(op byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = op
	}
	return b
}

// TestCheckPassesWhatTheEngineNeverRuns: a costly opcode the engine cannot
// reach, or one that fails for another reason, is not refused.
func TestCheckPassesWhatTheEngineNeverRuns(t *testing.T) {
	big := numPush(1 << 20)
	mul := cat(big, big, ops(script.OpMUL))
	cases := map[string]struct{ lock, unlock []byte }{
		"inside OP_0 OP_IF":                    {cat(ops(script.Op0, script.OpIF), mul, ops(script.OpENDIF, script.Op1)), nil},
		"inside OP_1 OP_NOTIF":                 {cat(ops(script.Op1, script.OpNOTIF), mul, ops(script.OpENDIF, script.Op1)), nil},
		"in the OP_ELSE of OP_1":               {cat(ops(script.Op1, script.OpIF, script.Op1, script.OpELSE), mul, ops(script.OpENDIF)), nil},
		"inside OP_DEPTH OP_IF":                {cat(ops(script.OpDEPTH, script.OpIF), mul, ops(script.OpENDIF, script.Op1)), nil},
		"after a top-level RETURN":             {cat(ops(script.Op1, script.OpRETURN), mul), nil},
		"after a RETURN in a branch":           {cat(ops(script.Op1, script.Op1, script.OpIF, script.OpRETURN, script.OpENDIF), mul), nil},
		"after an undecodable push":            {mul, ops(script.Op1, script.OpPUSHDATA2, 0xff)},
		"after OP_VERIFY of OP_0":              {cat(ops(script.Op0, script.OpVERIFY), mul), nil},
		"after a second OP_ELSE":               {cat(ops(script.Op1, script.OpIF, script.OpELSE, script.OpELSE), mul, ops(script.OpENDIF)), nil},
		"after an unmatched ENDIF":             {cat(ops(script.OpENDIF), mul), nil},
		"MUL missing an operand":               {cat(ops(script.OpMUL), big), nil},
		"divide by zero":                       {ops(script.Op1, script.Op0, script.OpDIV), nil},
		"multisig short of items":              {ops(script.Op2, script.Op3, script.OpCHECKMULTISIG), nil},
		"multisig m over n":                    {cat(ops(script.Op0, script.Op1, script.Op1), dataPush(le(5000)), ops(script.Op1, script.Op1, script.OpCHECKMULTISIG)), nil},
		"executing OP_VERIF, before Chronicle": {cat(ops(script.Op1, script.OpVERIF), mul, ops(script.OpENDIF)), nil},
	}
	for name, c := range cases {
		flags := afterChronicle
		if strings.HasSuffix(name, "before Chronicle") {
			flags = afterGenesis
		}
		s := lockSpend(c.lock, c.unlock)
		s.tx.Version = 2
		if err := check(s, flags); err != nil {
			t.Errorf("%s: Check = %v, want nil", name, err)
		}
	}
	// The same MUL behind a branch the analysis cannot decide is refused.
	unknown := cat(ops(script.OpSHA256, script.OpIF), mul, ops(script.OpENDIF, script.Op1))
	if err := check(lockSpend(unknown, []byte{script.Op1}), afterChronicle); !errors.Is(err, ErrTooCostly) {
		t.Errorf("an undecided branch: Check = %v, want ErrTooCostly", err)
	}
}

// TestCheckJoinsTheUnlockingScriptsEnds: the locking script starts from
// every stack the unlocking script may end with: here the empty one of an
// OP_RETURN in a branch on nine zero bytes, which the engine skips, and the
// 1 MiB number of the normal end, which the locking script's OP_MUL reads.
func TestCheckJoinsTheUnlockingScriptsEnds(t *testing.T) {
	unlock := cat(dataPush(make([]byte, 9)), ops(script.OpIF, script.OpRETURN, script.OpENDIF), numPush(1<<20))
	s := lockSpend(ops(script.OpDUP, script.OpMUL), unlock)
	s.tx.Version = 2
	if err := check(s, afterChronicle); !errors.Is(err, ErrTooCostly) || !containsWord(err.Error(), "OP_MUL") {
		t.Fatalf("Check = %v, want ErrTooCostly at OP_MUL", err)
	}
}

// TestCheckInputs: inputs the engine refuses before executing, an output
// created before Genesis, and a done context.
func TestCheckInputs(t *testing.T) {
	s := bigMulDiv(1 << 20)
	ctx := context.Background()
	if err := Check(ctx, nil, 0, s.prevout, afterChronicle); err != nil {
		t.Errorf("nil tx: %v", err)
	}
	if err := Check(ctx, s.tx, 1, s.prevout, afterChronicle); err != nil {
		t.Errorf("vin out of range: %v", err)
	}
	if err := Check(ctx, s.tx, -1, s.prevout, afterChronicle); err != nil {
		t.Errorf("negative vin: %v", err)
	}
	if err := Check(ctx, s.tx, 0, nil, afterChronicle); err != nil {
		t.Errorf("nil prevout: %v", err)
	}
	if err := Check(ctx, s.tx, 0, &transaction.TransactionOutput{}, afterChronicle); err != nil {
		t.Errorf("nil locking script: %v", err)
	}
	if err := Check(ctx, s.tx, 0, s.prevout, beforeGenesis); err != nil {
		t.Errorf("before Genesis: %v", err)
	}
	s.tx.Inputs[0].UnlockingScript = nil
	if err := Check(nil, s.tx, 0, s.prevout, afterChronicle); !errors.Is(err, ErrTooCostly) { //nolint:staticcheck // a nil context is handled
		t.Errorf("nil unlocking script and context: %v, want ErrTooCostly", err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := Check(done, s.tx, 0, s.prevout, afterChronicle); !errors.Is(err, context.Canceled) {
		t.Errorf("done context: %v, want context.Canceled", err)
	}
}
