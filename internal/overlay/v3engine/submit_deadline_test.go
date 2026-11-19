//go:build unix

package v3engine

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// expensiveScriptBEEF returns a valid-looking V1 BEEF whose verification is
// pure CPU: the tip spends an unmined output whose locking script pushes 1 MiB
// and then runs OP_DUP OP_SHA256 OP_DROP over it costlyRounds (16,000) times.
// Each round copies and hashes the 1 MiB element, so spv.Verify runs for
// about 6.9 s on a 1.1 MB body (measured without -race).
func expensiveScriptBEEF(t *testing.T) []byte {
	t.Helper()
	lock := &script.Script{}
	if err := lock.AppendPushData(bytes.Repeat([]byte{0x01}, 1<<20)); err != nil {
		t.Fatalf("AppendPushData: %v", err)
	}
	for i := 0; i < costlyRounds; i++ {
		_ = lock.AppendOpcodes(script.OpDUP, script.OpSHA256, script.OpDROP)
	}
	costly := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 1})

	spend := transaction.NewTransaction()
	spend.AddInputFromTx(costly, 0, nil)
	spend.Inputs[0].UnlockingScript = &script.Script{}
	opReturn := script.Script{script.OpFALSE, script.OpRETURN}
	spend.AddOutput(&transaction.TransactionOutput{LockingScript: &opReturn, Satoshis: 0})
	beef, err := spend.BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}
	return beef
}

// processCPU returns the CPU time, user plus system, this process has used.
func processCPU(t *testing.T) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// TestSubmitHandler_DeadlineStopsExpensiveScript: POST /submit runs
// spv.Verify on a client's BEEF with no login, and script cost grows with the
// BEEF without limit. The route must give up at its deadline with a 504 in the
// canonical error envelope, and verification must stop with it rather than
// keep a CPU busy after the reply.
func TestSubmitHandler_DeadlineStopsExpensiveScript(t *testing.T) {
	const timeout = time.Second
	eng, _ := newTestEngine(t)
	h := NewHandlers(eng)
	h.SubmitTimeout = timeout
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	beef := expensiveScriptBEEF(t)
	start := time.Now()
	status, raw := postSubmit(t, srv.URL, beef)
	elapsed := time.Since(start)
	t.Logf("%d-byte BEEF answered %d after %v (deadline %v)", len(beef), status, elapsed, timeout)
	if status != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 at the deadline, got %d: %s", status, raw)
	}
	assertCanonicalErrorEnvelope(t, bytes.NewReader(raw), "context deadline exceeded")
	if elapsed > timeout+3*time.Second {
		t.Fatalf("the reply took %v, more than the %v deadline plus 3 s", elapsed, timeout)
	}

	// A verification still running would use about one CPU-second per second.
	before := processCPU(t)
	time.Sleep(time.Second)
	used := processCPU(t) - before
	t.Logf("CPU used in the second after the reply: %v", used)
	if used > 300*time.Millisecond {
		t.Fatalf("the process used %v of CPU in the second after the reply: verification kept running", used)
	}
}

// TestSubmitHandler_DefaultDeadlineIsTheShims: an unset SubmitTimeout uses
// DefaultSubmitTimeout, the legacy /overlay/submit shim's 45 s.
func TestSubmitHandler_DefaultDeadlineIsTheShims(t *testing.T) {
	if got := (&Handlers{}).submitTimeout(); got != 45*time.Second {
		t.Fatalf("default submit deadline is %v, want 45s", got)
	}
}
