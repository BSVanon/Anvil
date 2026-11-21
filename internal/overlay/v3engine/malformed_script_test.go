package v3engine

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// B1 (cold review round 4): an unlocking script that ends in an undecodable
// instruction and spends a locking script that is one large push used to
// make a signature opcode's reparse (go-sdk v1.7.7,
// script/interpreter/thread.go:1110-1162) turn that push into millions of
// ParsedOpcodes. routeguard.checkScripts refuses it, via
// scriptcost.EndsMalformed, before spv.Verify or any interpreter work runs
// (internal/overlay/routeguard/scriptcheck.go). These tests pin that for
// every affected opcode on /submit: refused promptly, with the coded 400,
// and with no meaningful heap growth -- proof the interpreter never reparses
// the locking script, not just that the status code is 400.

// malformedScriptBodyBytes is the locking script's push size for these
// tests: large enough that an unguarded reparse (one ~64-128 byte
// ParsedOpcode per byte, per the B1 measurement) would add tens of MiB,
// clearly over malformedScriptHeapBound, while small enough that building it
// (bytes.Repeat) and, if the guard ever regressed, even reparsing it, stays
// fast enough for a suite run on every commit.
const malformedScriptBodyBytes = 300_000

// malformedScriptHeapBound is the most extra heap a refusal before any
// script runs should ever need: parsing a few-hundred-KB BEEF and building
// its error response. An unguarded reparse of malformedScriptBodyBytes would
// need on the order of malformedScriptBodyBytes*64 bytes (over 18 MiB), so
// this bound is well under what a regression would produce and well over
// what the guarded path actually uses.
const malformedScriptHeapBound = 8 << 20

// malformedScriptWallClockBound is how long a refused submit may take. The
// original 15 MB, single-CHECKSIG case (cold review round 4) reparsed in
// about 1.03 s once already past the guard that did not yet exist; refused
// before any of that work, this must return close to instantly.
const malformedScriptWallClockBound = 2 * time.Second

func submitHandler(t *testing.T) http.Handler {
	t.Helper()
	eng, _ := newTestEngine(t)
	mux := http.NewServeMux()
	NewHandlers(eng).Register(mux, nil)
	return mux
}

func submitInProcess(t *testing.T, handler http.Handler, body []byte) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-topics", `["tm_uhrp"]`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestSubmit_RefusesMalformedUnlockingScript(t *testing.T) {
	for _, op := range []overlaytest.SigOpcode{
		overlaytest.CheckSig, overlaytest.CheckSigVerify,
		overlaytest.CheckMultiSig, overlaytest.CheckMultiSigVerify,
	} {
		t.Run(op.String(), func(t *testing.T) {
			beef := overlaytest.MalformedReparseBEEF(t, malformedScriptBodyBytes, 1, op)
			handler := submitHandler(t)

			var code int
			var body []byte
			start := time.Now()
			peak, base := hostiletest.HeapPeak(func() {
				code, body = submitInProcess(t, handler, beef)
			})
			took := time.Since(start)
			t.Logf("%s: %d bytes refused in %v, heap peak %.1f MiB over %.1f MiB base",
				op, len(beef), took, float64(peak)/(1<<20), float64(base)/(1<<20))

			if code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d %s, want 400", op, code, body)
			}
			if !strings.Contains(string(body), `"code":"`+routeguard.MalformedScriptCode+`"`) {
				t.Fatalf("%s: body %s, want code %s", op, body, routeguard.MalformedScriptCode)
			}
			if took > malformedScriptWallClockBound {
				t.Errorf("%s: refused after %v, want under %v (the interpreter must never run)", op, took, malformedScriptWallClockBound)
			}
			if peak > malformedScriptHeapBound {
				t.Errorf("%s: heap peak %d bytes over base, want under %d (the locking script must never be reparsed)",
					op, peak, malformedScriptHeapBound)
			}
		})
	}
}

func honestSignatureBEEFs(t *testing.T) map[string][]byte {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	build := func(lock *script.Script) *transaction.Transaction {
		parent := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 50_000})
		child := transaction.NewTransaction()
		child.AddInputFromTx(parent, 0, nil)
		child.AddOutput(uhrpOutput(t, strings.Repeat("a1", 32)))
		return child
	}

	addr, err := script.NewAddressFromPublicKey(key.PubKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	p2pkhLock, err := p2pkh.Lock(addr)
	if err != nil {
		t.Fatal(err)
	}
	p2pkhSpend := build(p2pkhLock)
	p2pkhUnlocker, err := p2pkh.Unlock(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	p2pkhSpend.Inputs[0].UnlockingScript, err = p2pkhUnlocker.Sign(p2pkhSpend, 0)
	if err != nil {
		t.Fatal(err)
	}

	multisigLock := script.Script{script.Op1}
	if err := multisigLock.AppendPushData(key.PubKey().Compressed()); err != nil {
		t.Fatal(err)
	}
	multisigLock = append(multisigLock, script.Op1, script.OpCHECKMULTISIG)
	multisigSpend := build(&multisigLock)
	hash, err := multisigSpend.CalcInputSignatureHash(0, sighash.AllForkID)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := key.Sign(hash)
	if err != nil {
		t.Fatal(err)
	}
	sigWithType := append(sig.Serialize(), byte(sighash.AllForkID))
	multisigUnlock := script.Script{script.Op0}
	if err := multisigUnlock.AppendPushData(sigWithType); err != nil {
		t.Fatal(err)
	}
	multisigSpend.Inputs[0].UnlockingScript = &multisigUnlock

	beefs := map[string][]byte{}
	for name, tx := range map[string]*transaction.Transaction{
		"P2PKH":           p2pkhSpend,
		"1-of-1 multisig": multisigSpend,
	} {
		beef, err := tx.BEEF()
		if err != nil {
			t.Fatalf("%s BEEF: %v", name, err)
		}
		beefs[name] = beef
	}
	return beefs
}

func TestSubmit_AdmitsHonestSignatureScripts(t *testing.T) {
	for name, beef := range honestSignatureBEEFs(t) {
		t.Run(name, func(t *testing.T) {
			code, body := submitInProcess(t, submitHandler(t), beef)
			if code != http.StatusOK {
				t.Fatalf("status = %d %s, want 200", code, body)
			}
		})
	}
}
