package v3engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// guardedServer serves the canonical routes of eng under the guard g.
func guardedServer(t *testing.T, eng *engine.Engine, g *routeguard.Guard) string {
	t.Helper()
	h := NewHandlers(eng)
	h.Guard = g
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// freshGuard is a guard with the production budgets, of the test's own.
func freshGuard(cpuSlots int64) *routeguard.Guard {
	return routeguard.New(routeguard.MemoryBudget-routeguard.ExecAllowance, cpuSlots, routeguard.JSONSlots, routeguard.Wait)
}

// submitTo POSTs body to url's /submit for tm_uhrp, waiting for 100 Continue
// before it sends the body, as a careful client does, so a refusal costs the
// client no upload. It returns the status, the body and how long it took.
func submitTo(ctx context.Context, url string, body []byte) (int, []byte, time.Duration, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url+"/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-topics", `["`+topics.UHRPTopicName+`"]`)
	req.Header.Set("Expect", "100-continue")
	client := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: time.Minute}}
	defer client.CloseIdleConnections()
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, time.Since(start), err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, time.Since(start), nil
}

// cpuBombBEEF spends a locking script that doubles a 1 KB push to 32 MiB with
// OP_CAT and then hashes the result n times: a few KB of BEEF whose scripts
// take far longer than routeguard.VerifyBudget to verify.
func cpuBombBEEF(t *testing.T, n int) (*transaction.Transaction, []byte) {
	t.Helper()
	lock := &script.Script{}
	_ = lock.AppendPushData(bytes.Repeat([]byte{0x42}, 1024))
	for i := 0; i < 15; i++ {
		_ = lock.AppendOpcodes(script.OpDUP, script.OpCAT)
	}
	for i := 0; i < n; i++ {
		_ = lock.AppendOpcodes(script.OpDUP, script.OpSHA256, script.OpDROP)
	}
	_ = lock.AppendOpcodes(script.OpDROP, script.OpTRUE)
	beef := spendWith(t, lock, &script.Script{}, &transaction.TransactionOutput{LockingScript: &script.Script{script.OpTRUE}, Satoshis: 1})
	tx, err := transaction.NewTransactionFromBEEF(beef)
	if err != nil {
		t.Fatal(err)
	}
	return tx, beef
}

// smallUHRP is a valid, distinct UHRP advertisement submit.
func smallUHRP(t *testing.T, i int) []byte {
	return buildUHRPTaggedBEEF(t, fmt.Sprintf("%064x", 0xabc0000+i), fmt.Sprintf("https://g.test/%d", i), "image/png", false).Beef
}

// TestGuard_MaxSizeSubmitsStayWithinTheBudget: 64 concurrent submits of the
// largest body the route accepts keep the heap within routeguard.MemoryBudget.
// Each is sent 100 Continue by the first read of its body; those the
// big-body slot and the budget cannot hold are then answered 503 with
// Retry-After at about routeguard.Wait, the rest of their bodies unread, and
// get that answer rather than a reset though they are still sending; the
// rest are served.
func TestGuard_MaxSizeSubmitsStayWithinTheBudget(t *testing.T) {
	eng, _ := newTestEngine(t)
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	body, _ := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: opReturn(int(routeguard.MaxBEEFBody) - 4096)}).BEEF()
	if int64(len(body)) > routeguard.MaxBEEFBody {
		t.Fatalf("fixture of %d bytes is over the cap", len(body))
	}
	const n = 64
	type result struct {
		code    int
		elapsed time.Duration
		err     error
	}
	results := make([]result, n)
	peak, _ := hostiletest.HeapPeak(func() {
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code, _, elapsed, err := submitTo(context.Background(), url, body)
				results[i] = result{code, elapsed, err}
			}()
		}
		wg.Wait()
	})
	served, busy := 0, 0
	var slowestBusy time.Duration
	for i, r := range results {
		switch {
		case r.err != nil:
			t.Errorf("submit %d: %v", i, r.err)
		case r.code == http.StatusOK:
			served++
		case r.code == http.StatusServiceUnavailable:
			busy++
			slowestBusy = max(slowestBusy, r.elapsed)
		default:
			t.Errorf("submit %d answered %d", i, r.code)
		}
	}
	t.Logf("%d max-size submits of %d bytes: %d served, %d answered 503 (slowest %v); peak heap in use %.1f MiB of a %d MiB budget",
		n, len(body), served, busy, slowestBusy, float64(peak)/(1<<20), routeguard.MemoryBudget>>20)
	if served == 0 || busy == 0 {
		t.Errorf("want some served and some refused, got %d and %d", served, busy)
	}
	if slowestBusy > routeguard.Wait+3*time.Second {
		t.Errorf("a refusal took %v, want about %v", slowestBusy, routeguard.Wait)
	}
	if peak > uint64(routeguard.MemoryBudget) {
		t.Errorf("peak heap in use %.1f MiB, over the %d MiB budget", float64(peak)/(1<<20), routeguard.MemoryBudget>>20)
	}
}

// TestGuard_HonestLoadIsNotRefused: 8 small submits and 32 lookups at once,
// with the production budgets, are all served.
func TestGuard_HonestLoadIsNotRefused(t *testing.T) {
	eng, _ := newTestEngine(t)
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	q, _ := json.Marshal(map[string]any{"service": topics.UHRPLookupServiceName, "query": topics.UHRPLookupQuery{ContentHash: fmt.Sprintf("%064x", 0xabc0000)}})
	var wg sync.WaitGroup
	codes := make(chan string, 40)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, raw, _, err := submitTo(context.Background(), url, smallUHRP(t, i))
			codes <- fmt.Sprintf("submit %d: %d %v %.80s", i, code, err, raw)
		}()
	}
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := (&http.Client{}).Post(url+"/lookup", "application/json", bytes.NewReader(q))
			if err != nil {
				codes <- fmt.Sprintf("lookup %d: 0 %v", i, err)
				return
			}
			resp.Body.Close()
			codes <- fmt.Sprintf("lookup %d: %d <nil>", i, resp.StatusCode)
		}()
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if !strings.Contains(c, ": 200 <nil>") {
			t.Errorf("not served: %s", c)
		}
	}
}

// TestGuard_CPUSlotReturnsAtSteakReady: a submit gives its CPU slot back once
// the engine reports its STEAK ready, before its commit. With one slot, a
// second submit is served while the first is held inside its commit.
func TestGuard_CPUSlotReturnsAtSteakReady(t *testing.T) {
	se := newStallingEngine(t)
	fx := newCommitFixture(t)
	admitOffer(t, se.eng, fx)
	url := guardedServer(t, se.eng, freshGuard(1))
	release, began := make(chan struct{}), make(chan struct{})
	se.stall.arm("InsertOutputs", func() {
		close(began)
		<-release
	})
	first := make(chan int, 1)
	go func() {
		status, _ := postTopics(t, url, fx.spendBEEF, commitTopics)
		first <- status
	}()
	select {
	case <-began:
	case <-time.After(10 * time.Second):
		t.Fatal("the first submit never reached its commit")
	}
	code, raw, elapsed, err := submitTo(context.Background(), url, smallUHRP(t, 1))
	close(release)
	if err != nil || code != http.StatusOK {
		t.Fatalf("second submit while the first is held in its commit: %d %v %s (after %v)", code, err, raw, elapsed)
	}
	t.Logf("second submit served in %v while the first was held in its commit", elapsed)
	if status := <-first; status != http.StatusOK {
		t.Fatalf("the held submit answered %d", status)
	}
}

// TestGuard_ScriptsOverTheVerifyBudgetAnswer422: a few KB of BEEF whose
// scripts would verify for far longer than routeguard.VerifyBudget is refused
// at the budget with 422 ERR_VALIDATION_BUDGET, before the engine sees it.
func TestGuard_ScriptsOverTheVerifyBudgetAnswer422(t *testing.T) {
	tx, beef := cpuBombBEEF(t, 3000)
	eng, _ := newTestEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), routeguard.VerifyBudget+2*time.Second)
	start := time.Now()
	ok, err := spv.Verify(ctx, tx, eng.ChainTracker, nil)
	cancel()
	if ctx.Err() == nil {
		t.Fatalf("the fixture verified in %v (ok=%v, err=%v); it must take longer than %v", time.Since(start), ok, err, routeguard.VerifyBudget+2*time.Second)
	}
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	logs := watchRefusals(t)
	code, raw, elapsed, err := submitTo(context.Background(), url, beef)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d-byte BEEF answered %d after %v: %s", len(beef), code, elapsed, raw)
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(raw), `"code":"`+routeguard.ValidationBudgetCode+`"`) {
		t.Fatalf("want 422 %s, got %d %s", routeguard.ValidationBudgetCode, code, raw)
	}
	if elapsed > routeguard.VerifyBudget+2*time.Second {
		t.Fatalf("refused after %v, want about %v", elapsed, routeguard.VerifyBudget)
	}
	logs.assertLogged(t, http.StatusUnprocessableEntity, refusallog.ReasonValidationBudget, "/submit")
}

// TestGuard_DisconnectEndsTheVerification: a client that goes away while its
// scripts verify takes the verification with it. With one CPU slot, the next
// submit is served at once rather than after the abandoned one's budget.
func TestGuard_DisconnectEndsTheVerification(t *testing.T) {
	_, bomb := cpuBombBEEF(t, 3000)
	eng, _ := newTestEngine(t)
	url := guardedServer(t, eng, freshGuard(1))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if code, _, _, err := submitTo(ctx, url, bomb); err == nil {
		t.Fatalf("the abandoned submit answered %d", code)
	}
	time.Sleep(100 * time.Millisecond)
	code, raw, elapsed, err := submitTo(context.Background(), url, smallUHRP(t, 2))
	if err != nil || code != http.StatusOK {
		t.Fatalf("submit after a disconnect: %d %v %s", code, err, raw)
	}
	t.Logf("submit after the disconnect served in %v", elapsed)
	if elapsed > routeguard.Wait/2 {
		t.Fatalf("served after %v: the abandoned verification kept the CPU slot", elapsed)
	}
}

// TestGuard_ScriptOverTheInstructionCapAnswers400: a script over
// routeguard.MaxScriptOps instructions is refused with 400
// ERR_BEEF_TOO_COMPLEX before anything parses it into opcodes.
func TestGuard_ScriptOverTheInstructionCapAnswers400(t *testing.T) {
	lock := script.Script(append(bytes.Repeat([]byte{script.OpNOP}, routeguard.MaxScriptOps), script.OpTRUE))
	beef := spendWith(t, &lock, &script.Script{}, &transaction.TransactionOutput{LockingScript: &script.Script{script.OpTRUE}, Satoshis: 1})
	out := script.Script(append([]byte{script.OpTRUE}, bytes.Repeat([]byte{script.OpNOP}, routeguard.MaxScriptOps)...))
	wide, _ := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &out}).BEEF()
	eng, _ := newTestEngine(t)
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	logs := watchRefusals(t)
	for name, body := range map[string][]byte{"verified input": beef, "output": wide} {
		code, raw, _, err := submitTo(context.Background(), url, body)
		if err != nil || code != http.StatusBadRequest || !strings.Contains(string(raw), `"code":"`+beefscan.Code+`"`) {
			t.Errorf("%s over the cap: %d %v %s", name, code, err, raw)
		}
	}
	logs.assertLogged(t, http.StatusBadRequest, refusallog.ReasonTooComplex, "/submit")
}
