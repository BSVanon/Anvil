package overlaytest

import (
	"bytes"
	"encoding/binary"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// SigOpcode identifies which signature-checking opcode
// MalformedReparseBEEF's unlocking script ends each of its k copies with.
// All four are go-sdk v1.7.7's affected opcodes (cold review round 4, B1):
// each can call subScriptForChecksig (script/interpreter/thread.go:1110-1162).
type SigOpcode int

const (
	CheckSig SigOpcode = iota
	CheckSigVerify
	CheckMultiSig
	CheckMultiSigVerify
)

// String names op the way go-sdk's script package does, for test names and
// failure messages.
func (op SigOpcode) String() string {
	switch op {
	case CheckSig:
		return "OP_CHECKSIG"
	case CheckSigVerify:
		return "OP_CHECKSIGVERIFY"
	case CheckMultiSig:
		return "OP_CHECKMULTISIG"
	case CheckMultiSigVerify:
		return "OP_CHECKMULTISIGVERIFY"
	default:
		return "unknown SigOpcode"
	}
}

// MalformedReparseBEEF returns the BEEF of a version-2 (post-Chronicle)
// transaction that spends a funding-derived parent whose output 0 is a
// single push of n arbitrary bytes, unlocked by k copies of a signature
// check using op and ending in a truncated OP_PUSHDATA1.
//
// This is the B1 shape (cold review round 4): under Chronicle, op executing
// inside the unlocking script builds its scriptCode from the unlocking
// script joined with the locking script (subScriptForChecksig). Because the
// unlocking script's last parsed instruction is malformed (a push whose
// length runs past the script's end), go-sdk v1.7.7 re-decodes that tail
// joined with the whole locking script as one byte stream (reparseJoined,
// script/interpreter/thread.go:1123-1162): the n-byte push becomes
// approximately n 64-byte ParsedOpcodes -- a heap bomb reachable with no
// login, no funds spent and no valid signature, since the interpreter
// never gets far enough to check one. Anvil's routeguard refuses this
// before any script runs (scriptcost.EndsMalformed,
// internal/overlay/routeguard/scriptcheck.go). This builder lets both
// /submit (v3engine) and /overlay/submit (legacyshim) regress every
// affected opcode against the same, independently reasoned-through shape,
// without duplicating it.
//
// k's signature and public key are real (a freshly generated key signs a
// fixed message), not the input's actual sighash preimage, so the
// signature check itself would fail if ever reached -- irrelevant here
// since the fix refuses the submit on the unlocking script's shape alone,
// before the interpreter looks at the signature at all.
func MalformedReparseBEEF(t testing.TB, n, k int, op SigOpcode) []byte {
	t.Helper()
	lock := make([]byte, 5, 5+n)
	lock[0] = script.OpPUSHDATA4
	binary.LittleEndian.PutUint32(lock[1:5], uint32(n)) //nolint:gosec // n is a test-chosen size, not attacker input
	lock = append(lock, bytes.Repeat([]byte{script.OpNOP}, n)...)
	ls := script.Script(lock)
	parent := SpendingTx(t, &transaction.TransactionOutput{LockingScript: &ls, Satoshis: 50_000})

	child := transaction.NewTransaction()
	child.Version = 2
	child.AddInputFromTx(parent, 0, nil)

	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := priv.Sign(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	der := append(sig.Serialize(), 0x41)
	pk := priv.PubKey().Compressed()

	var unlock []byte
	push := func(b []byte) { unlock = append(append(unlock, byte(len(b))), b...) } //nolint:gosec // der/pk are well under 256 bytes
	for i := 0; i < k; i++ {
		switch op {
		case CheckSig:
			push(der)
			push(pk)
			unlock = append(unlock, script.OpCHECKSIG)
			if i+1 < k {
				unlock = append(unlock, script.OpDROP)
			}
		case CheckSigVerify:
			push(der)
			push(pk)
			unlock = append(unlock, script.OpCHECKSIGVERIFY)
		case CheckMultiSig:
			unlock = append(unlock, script.Op0)
			push(der)
			unlock = append(unlock, script.Op1)
			push(pk)
			unlock = append(unlock, script.Op1, script.OpCHECKMULTISIG)
			if i+1 < k {
				unlock = append(unlock, script.OpDROP)
			}
		case CheckMultiSigVerify:
			unlock = append(unlock, script.Op0)
			push(der)
			unlock = append(unlock, script.Op1)
			push(pk)
			unlock = append(unlock, script.Op1, script.OpCHECKMULTISIGVERIFY)
		default:
			t.Fatalf("overlaytest: MalformedReparseBEEF: unknown SigOpcode %d", op)
		}
	}
	unlock = append(unlock, script.OpPUSHDATA1, 0x05) // truncated: undecodable tail
	us := script.Script(unlock)
	child.Inputs[0].UnlockingScript = &us
	out := script.Script{script.OpTRUE}
	child.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: 1000})

	beef, err := child.BEEF()
	if err != nil {
		t.Fatal(err)
	}
	return beef
}
