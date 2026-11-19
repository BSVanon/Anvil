package v3engine

import (
	"encoding/binary"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// minimalNum is n as a minimally encoded positive script number.
func minimalNum(n int) []byte {
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append(b, byte(v))
	}
	if len(b) > 0 && b[len(b)-1]&0x80 != 0 {
		b = append(b, 0)
	}
	return b
}

// bigPush is a PUSHDATA4 of an n-byte positive minimal number drawn from
// seed.
func bigPush(n int, seed uint64) []byte {
	out := binary.LittleEndian.AppendUint32([]byte{script.OpPUSHDATA4}, uint32(n)) //nolint:gosec // n < 2^32
	x := seed
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out = append(out, byte(x))
	}
	out[len(out)-1] = 0x41
	return out
}

// spendScriptBEEF is a BEEF of a transaction spending, with unlock, an output
// locked by lock of a transaction that spends the funding output.
func spendScriptBEEF(t *testing.T, unlock, lock []byte) []byte {
	t.Helper()
	ls, us := script.Script(lock), script.Script(unlock)
	parent := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &ls, Satoshis: 50_000})
	child := transaction.NewTransaction()
	child.AddInputFromTx(parent, 0, nil)
	child.Inputs[0].UnlockingScript = &us
	child.AddOutput(&transaction.TransactionOutput{LockingScript: &script.Script{script.OpTRUE}, Satoshis: 1000})
	beef, err := child.BEEF()
	if err != nil {
		t.Fatal(err)
	}
	return beef
}

// TestSubmit_RefusesAnOpcodeOverItsCost: the shapes the third review timed
// past the verification budget, one opcode each that the engine does not
// interrupt, are refused with 400 ERR_BEEF_TOO_COMPLEX before any script
// runs: an OP_CHECKMULTISIG of 74,973 signatures and keys whose FindAndDelete
// pre-pass took 14.6 s (90.7 s, answered 504, behind a 15 MB push), an
// OP_DIV of a 16 MB number by an 8 MB one, and an OP_MUL then OP_DIV of 5 MB
// numbers (10.5 s).
func TestSubmit_RefusesAnOpcodeOverItsCost(t *testing.T) {
	_, _, url := normEngine(t)
	const a, b = 24990, 24990
	multisig := []byte{}
	for i := 0; i < a; i++ {
		multisig = append(multisig, script.Op3DUP)
	}
	n := minimalNum(3 + 3*a)
	multisig = append(append(append(multisig, byte(len(n))), n...), script.Op1, script.Op1, script.Op1)
	for i := 0; i < b; i++ {
		multisig = append(multisig, script.Op3DUP)
	}
	k := minimalNum(3 + 3*b)
	multisig = append(append(append(multisig, byte(len(k))), k...), script.OpCHECKMULTISIG)
	padded := append(binary.LittleEndian.AppendUint32([]byte{script.OpPUSHDATA4}, 15_000_000), make([]byte, 15_000_000)...)
	padded = append(append(padded, script.OpDROP), multisig...)

	div := append(bigPush(8_000_000, 0x2545f4914f6cdd1d), script.OpDUP, script.OpDUP, script.OpCAT, script.OpSWAP, script.OpDIV, script.OpDROP, script.OpTRUE)
	var mulDiv []byte
	for _, seed := range []uint64{0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9, 0x94d049bb133111eb} {
		mulDiv = append(mulDiv, bigPush(5_000_000, seed)...)
	}
	mulDiv = append(mulDiv, script.OpROT, script.OpROT, script.OpMUL, script.OpSWAP, script.OpDIV, script.OpDROP, script.OpTRUE)

	for _, c := range []struct {
		name, opcode string
		unlock, lock []byte
	}{
		{"multisig of 74,973", "OP_CHECKMULTISIG", []byte{script.Op0, script.Op1, script.Op1, script.Op1}, multisig},
		{"multisig of 74,973 over 15 MB", "OP_CHECKMULTISIG", []byte{script.Op0, script.Op1, script.Op1, script.Op1}, padded},
		{"16 MB by 8 MB", "OP_DIV", nil, div},
		{"5 MB products", "OP_MUL", nil, mulDiv},
	} {
		body := spendScriptBEEF(t, c.unlock, c.lock)
		start := time.Now()
		code, resp := postSubmit(t, url, body)
		took := time.Since(start)
		t.Logf("%s: %d bytes -> %d in %v", c.name, len(body), code, took)
		if code != http.StatusBadRequest || !strings.Contains(string(resp), beefscan.Code) || !strings.Contains(string(resp), c.opcode) {
			t.Errorf("%s: %d %.300s, want 400 %s naming %s", c.name, code, resp, beefscan.Code, c.opcode)
		}
		if took > 3*time.Second {
			t.Errorf("%s: refused after %v", c.name, took)
		}
	}
}
