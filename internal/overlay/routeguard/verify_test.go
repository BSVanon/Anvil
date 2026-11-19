package routeguard

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// spendBEEF is the BEEF of a transaction spending an output locked by lock
// with an empty unlocking script.
func spendBEEF(t *testing.T, lock script.Script) []byte {
	t.Helper()
	parent := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1000})
	child := transaction.NewTransaction()
	child.AddInputFromTx(parent, 0, nil)
	child.Inputs[0].UnlockingScript = &script.Script{}
	child.AddOutput(&transaction.TransactionOutput{LockingScript: &script.Script{script.OpTRUE}, Satoshis: 1})
	b, err := child.BEEF()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// preVerified reads beef through ReadBody on a new ticket of g and runs
// PreVerify on it without a chain tracker, so the ticket takes its slots but
// verifies nothing.
func preVerified(t *testing.T, g *Guard, beef []byte) (*Ticket, *Submit, error) {
	t.Helper()
	tk, err := g.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/submit", bytes.NewReader(beef))
	if _, err := tk.ReadBody(httptest.NewRecorder(), r, BEEFRoute); err != nil {
		t.Fatal(err)
	}
	sub, err := tk.PreVerify(context.Background(), nil, func(string) bool { return true }, beef, []string{"tm_test"})
	return tk, sub, err
}

// TestPreVerify_ScriptsThatWriteTakeTheOneExecutionSlot: a submit whose
// scripts may write new stack elements holds the execution slot until its
// steak is ready, so a second such submit gets ErrBusy at the guard's Wait,
// while one whose scripts only read runs beside it; once the first steak is
// ready the slot is handed on, after a collection.
func TestPreVerify_ScriptsThatWriteTakeTheOneExecutionSlot(t *testing.T) {
	g := New(1<<30, 4, 4, testWait)
	writer := spendBEEF(t, script.Script{script.Op1, script.Op1, script.OpCAT})
	reader := spendBEEF(t, script.Script{script.Op1, script.OpNOP})

	_, first, err := preVerified(t, g, writer)
	if err != nil {
		t.Fatalf("the first writing submit: %v", err)
	}
	second, _, err := preVerified(t, g, writer)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("a second writing submit while the first holds the slot: %v, want ErrBusy", err)
	}
	second.Close()
	_, beside, err := preVerified(t, g, reader)
	if err != nil {
		t.Fatalf("a reading submit beside the writing one: %v", err)
	}
	beside.Done()

	first.OnSteakReady(nil)(nil)
	_, next, err := preVerified(t, g, writer)
	if err != nil {
		t.Fatalf("a writing submit once the first steak is ready: %v", err)
	}
	next.Done()
	first.Done()
}

// TestPreVerify_RefusesAMalformedScriptBeforeAnySlot: cold review round 4
// cycle 6's "slot order" NIT -- the malformed-script scan ran inside
// checkScripts, after both the execution and CPU slots were taken -- fixed
// by scanMalformedScripts, called before either is taken. With the guard's
// one CPU slot held by another submit, a malformed submit is still refused
// with ErrMalformedScript at once: it never waits out the guard's Wait for a
// slot, and never gets ErrBusy instead.
func TestPreVerify_RefusesAMalformedScriptBeforeAnySlot(t *testing.T) {
	g := New(1<<30, 1, 4, testWait)
	holder := spendBEEF(t, script.Script{script.Op1, script.OpNOP}) // takes the one CPU slot, no execution slot
	_, held, err := preVerified(t, g, holder)
	if err != nil {
		t.Fatalf("occupying the one CPU slot: %v", err)
	}
	defer held.Done()

	beef := overlaytest.MalformedReparseBEEF(t, 1000, 1, overlaytest.CheckSig)
	start := time.Now()
	tk, _, err := preVerified(t, g, beef)
	took := time.Since(start)
	if !errors.Is(err, ErrMalformedScript) {
		t.Fatalf("a malformed submit while the one CPU slot is held: %v, want ErrMalformedScript", err)
	}
	tk.Close()
	if took > testWait/2 {
		t.Errorf("refused after %v, want at once, before any slot wait (got as far as the guard's Wait, %v)", took, testWait)
	}
}

// collections is how many garbage collections the process has run.
func collections() uint32 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.NumGC
}

// TestPreVerify_CollectsAfterScriptsThatWrite: with the collector otherwise
// off, the guard collects once it has verified scripts that may write new
// stack elements, so the engine's own verification does not stack on that
// one's garbage, and again before it hands the execution slot on, so the
// next writer starts from a collected heap.
func TestPreVerify_CollectsAfterScriptsThatWrite(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	g := New(1<<30, 4, 4, testWait)
	writer := spendBEEF(t, script.Script{script.Op1, script.Op1, script.OpCAT})
	tk, err := g.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/submit", bytes.NewReader(writer))
	if _, err := tk.ReadBody(httptest.NewRecorder(), r, BEEFRoute); err != nil {
		t.Fatal(err)
	}
	before := collections()
	first, err := tk.PreVerify(context.Background(), &spv.GullibleHeadersClient{}, func(string) bool { return true }, writer, []string{"tm_test"})
	if err != nil {
		t.Fatalf("verifying the writer: %v", err)
	}
	if collections() == before {
		t.Fatal("no collection after verifying scripts that write")
	}
	before = collections()
	first.OnSteakReady(nil)(nil)
	_, next, err := preVerified(t, g, writer)
	if err != nil {
		t.Fatalf("the next writer: %v", err)
	}
	if collections() == before {
		t.Fatal("the execution slot was handed on before a collection")
	}
	next.Done()
	first.Done()
}
