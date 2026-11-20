package legacyshim_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/BSVanon/Anvil/internal/overlay/legacyshim"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// testPool is the heap the tests' guards share out: the production pool.
const testPool = routeguard.MemoryBudget - routeguard.ExecAllowance

// guardedShimServer serves shim's routes behind g and returns the URL.
func guardedShimServer(t *testing.T, shim *legacyshim.Shim, g *routeguard.Guard) string {
	t.Helper()
	shim.Guard = g
	mux := http.NewServeMux()
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// legacyPost POSTs body to url+path and returns the status, headers and body.
func legacyPost(t *testing.T, url, path, contentType string, body []byte, header map[string]string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(raw)
}

// submitUHRP POSTs beef to /overlay/submit for tm_uhrp, as binary.
func submitUHRP(t *testing.T, url string, beef []byte) (int, string) {
	t.Helper()
	code, _, raw := legacyPost(t, url, "/overlay/submit", "application/octet-stream", beef,
		map[string]string{"X-Topics": `["` + topics.UHRPTopicName + `"]`})
	return code, raw
}

// readQuestion reads question through tk's ReadBody as /overlay/query does,
// with no connection behind it, so a JSON route's ticket takes its JSON slot.
func readQuestion(tk *routeguard.Ticket, question []byte) error {
	r := httptest.NewRequest(http.MethodPost, "/overlay/query", bytes.NewReader(question))
	_, err := tk.ReadBody(httptest.NewRecorder(), r, routeguard.LookupRoute)
	return err
}

// beginLoopback begins a ticket for a request with no real connection behind
// it, from the loopback address, so that only the guard's own limits count
// it (routeguard's own clients_test.go tests a client's).
func beginLoopback(g *routeguard.Guard, jsonRoute bool) (*routeguard.Ticket, error) {
	r := httptest.NewRequest(http.MethodPost, "/overlay/query", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	return g.Begin(httptest.NewRecorder(), r, jsonRoute)
}

// assertIdle fails unless g has every byte and slot back: nothing a finished
// request held is still held. A JSON ticket takes its JSON slot once its body
// is in, so the probe reads one.
func assertIdle(t *testing.T, g *routeguard.Guard) {
	t.Helper()
	tk, err := beginLoopback(g, true)
	if err == nil {
		err = readQuestion(tk, []byte(`{}`))
		if err == nil {
			err = tk.Reserve(context.Background(), testPool-tk.Reserved())
		}
		if err == nil {
			err = tk.EnterCPU(context.Background())
		}
		tk.Close()
	}
	if err != nil {
		t.Fatalf("the guard did not get back what the request held: %v", err)
	}
}

// spendLock is a BEEF of a transaction spending an output locked by lock
// with an empty unlocking script.
func spendLock(t *testing.T, lock *script.Script) []byte {
	t.Helper()
	parent := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 50_000})
	child := transaction.NewTransaction()
	child.AddInputFromTx(parent, 0, nil)
	child.Inputs[0].UnlockingScript = &script.Script{}
	child.AddOutput(&transaction.TransactionOutput{LockingScript: &script.Script{script.OpTRUE}, Satoshis: 1})
	beef, err := child.BEEF()
	if err != nil {
		t.Fatal(err)
	}
	return beef
}

// TestLegacySubmit_GuardRefusalsAreCoded: /overlay/submit refuses, before
// the engine sees it, a script over routeguard.MaxScriptOps instructions with
// 400 ERR_BEEF_TOO_COMPLEX, and scripts that verify past
// routeguard.VerifyBudget with 422 ERR_VALIDATION_BUDGET at the budget, in
// the legacy envelope with the code beside the error; and the guard gets
// back everything each submit held.
func TestLegacySubmit_GuardRefusalsAreCoded(t *testing.T) {
	g := routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, 500*time.Millisecond)
	url := guardedShimServer(t, newWiredShim(t), g)
	logs := watchRefusals(t)

	nops := script.Script(append(bytes.Repeat([]byte{script.OpNOP}, routeguard.MaxScriptOps), script.OpTRUE))
	code, raw := submitUHRP(t, url, spendLock(t, &nops))
	if code != http.StatusBadRequest || !strings.Contains(raw, `"code":"`+beefscan.Code+`"`) || !strings.Contains(raw, `"error":`) {
		t.Errorf("a script over the instruction cap: %d %s", code, raw)
	}
	assertIdle(t, g)

	// A 32 MiB element hashed 3,000 times: the fixture the canonical route's
	// TestGuard_ScriptsOverTheVerifyBudgetAnswer422 times past the budget.
	bomb := &script.Script{}
	_ = bomb.AppendPushData(bytes.Repeat([]byte{0x42}, 1024))
	for i := 0; i < 15; i++ {
		_ = bomb.AppendOpcodes(script.OpDUP, script.OpCAT)
	}
	for i := 0; i < 3000; i++ {
		_ = bomb.AppendOpcodes(script.OpDUP, script.OpSHA256, script.OpDROP)
	}
	_ = bomb.AppendOpcodes(script.OpDROP, script.OpTRUE)
	start := time.Now()
	code, raw = submitUHRP(t, url, spendLock(t, bomb))
	elapsed := time.Since(start)
	t.Logf("scripts over the verification budget: %d after %v: %s", code, elapsed, raw)
	if code != http.StatusUnprocessableEntity || !strings.Contains(raw, `"code":"`+routeguard.ValidationBudgetCode+`"`) {
		t.Errorf("scripts over the verification budget: %d %s", code, raw)
	}
	if elapsed > routeguard.VerifyBudget+2*time.Second {
		t.Errorf("refused after %v, want about %v", elapsed, routeguard.VerifyBudget)
	}
	assertIdle(t, g)
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonTooComplex, "/overlay/submit")
	logs.assertLogged(t, http.StatusUnprocessableEntity, refusallog.ReasonValidationBudget, "/overlay/submit")
}

// TestLegacyQuery_BusyWhenEveryJSONSlotIsTaken: with every JSON slot held,
// /overlay/query answers 503 with Retry-After at once once its body is in,
// and serves again once a slot frees.
func TestLegacyQuery_BusyWhenEveryJSONSlotIsTaken(t *testing.T) {
	g := routeguard.New(testPool, routeguard.CPUSlots, 1, 500*time.Millisecond)
	url := guardedShimServer(t, newWiredShim(t), g)
	question := []byte(`{"service":"ls_uhrp","query":{"uhrpUrl":"none"}}`)

	held, err := beginLoopback(g, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := readQuestion(held, question); err != nil {
		t.Fatal(err)
	}
	logs := watchRefusals(t)
	start := time.Now()
	code, hdr, raw := legacyPost(t, url, "/overlay/query", "application/json", question, nil)
	if code != http.StatusServiceUnavailable || hdr.Get("Retry-After") == "" {
		t.Errorf("with every JSON slot held: %d, Retry-After %q: %s", code, hdr.Get("Retry-After"), raw)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("refused after %v, want at once", elapsed)
	}
	held.Close()
	if code, _, raw = legacyPost(t, url, "/overlay/query", "application/json", question, nil); code == http.StatusServiceUnavailable {
		t.Errorf("with the slot free again: %d %s", code, raw)
	}
	assertIdle(t, g)
	logs.assertLogged(t, http.StatusServiceUnavailable, refusallog.ReasonBusy, "/overlay/query")
}

// panickingEngine is an engine whose Submit panics, as go-sdk's broadcast
// and lookup code can below the engine.
type panickingEngine struct{}

func (panickingEngine) Submit(context.Context, overlay.TaggedBEEF, engine.SumbitMode, engine.OnSteakReady) (overlay.Steak, error) {
	panic("engine bug")
}

func (panickingEngine) Lookup(context.Context, *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return nil, errors.New("no lookups")
}

func (panickingEngine) ListTopicManagers() map[string]*overlay.MetaData          { return nil }
func (panickingEngine) ListLookupServiceProviders() map[string]*overlay.MetaData { return nil }

// TestLegacySubmit_EnginePanicIs500: a panic in the engine's submit, which
// runs on a goroutine of its own where net/http's recover cannot reach,
// answers 500 instead of ending the process, and the guard gets back the
// submit's ticket. The process surviving is the test reaching its end.
func TestLegacySubmit_EnginePanicIs500(t *testing.T) {
	g := routeguard.New(testPool, routeguard.CPUSlots, routeguard.JSONSlots, 500*time.Millisecond)
	url := guardedShimServer(t, &legacyshim.Shim{Engine: panickingEngine{}}, g)
	for i := 0; i < 2; i++ {
		code, raw := submitUHRP(t, url, []byte{0xde, 0xad, 0xbe, 0xef})
		if code != http.StatusInternalServerError || !strings.Contains(raw, "internal error while submitting") {
			t.Fatalf("submit %d to a panicking engine: %d %s", i, code, raw)
		}
		assertIdle(t, g)
	}
}
