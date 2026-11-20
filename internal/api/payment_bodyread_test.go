package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// clientResult carries a slow-body request's outcome back to the test
// goroutine — http.Client.Do runs in its own goroutine here so the test can
// inspect server-side state (PaymentGate.reservedPending) while the request
// is still in flight, and t.Fatalf must only ever run on the test goroutine.
type clientResult struct {
	resp *http.Response
	err  error
}

// TestSlowBodyDoesNotHoldPendingPlace: a request whose body stalls
// indefinitely must not hold a pending-place slot (payment_pending.go)
// while it stalls — cold review round 4's RISK 2: reservePending used to
// run before the body read, so up to maxPendingChallenges (1,024) such
// connections could exhaust every pending place and starve every
// legitimate challenge, with no bound on how long the stall could hold its
// slot (net/http sets no default per-request-body read timeout). The fix
// (payment_bodyread.go) reads the body, under its own size cap and
// deadline, before reservePending ever runs.
func TestSlowBodyDoesNotHoldPendingPlace(t *testing.T) {
	prevDeadline := bodyReadDeadline
	bodyReadDeadline = 150 * time.Millisecond
	defer func() { bodyReadDeadline = prevDeadline }()

	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pr, pw := io.Pipe()
	defer pw.Close()

	req, err := http.NewRequest("POST", ts.URL+"/data", pr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	done := make(chan clientResult, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		done <- clientResult{resp: resp, err: err}
	}()

	// Give the server time to reach the (still-blocked) body read, well
	// before bodyReadDeadline fires, then check pending-place state while
	// the connection is still stalled — this is the moment RISK 2 bites:
	// under the pre-fix ordering, reservePending already ran and holds a
	// slot right here, before the stalled read is even attempted.
	time.Sleep(50 * time.Millisecond)

	srv.paymentGate.mu.Lock()
	reserved := srv.paymentGate.reservedPending
	pending := len(srv.paymentGate.pendingChallenges)
	srv.paymentGate.mu.Unlock()
	if reserved != 0 || pending != 0 {
		t.Fatalf("a stalled body must not hold a pending-place slot while it stalls; got reservedPending=%d pendingChallenges=%d", reserved, pending)
	}

	// Let the deadline fire and the request complete.
	select {
	case res := <-done:
		if res.resp != nil {
			defer res.resp.Body.Close()
			if res.resp.StatusCode != http.StatusRequestTimeout {
				t.Fatalf("expected 408 once the stalled body's deadline fires, got %d", res.resp.StatusCode)
			}
		} else if res.err == nil {
			t.Fatal("expected either a response or a client error, got neither")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request did not complete after the body read deadline should have fired")
	}

	srv.paymentGate.mu.Lock()
	reserved = srv.paymentGate.reservedPending
	pending = len(srv.paymentGate.pendingChallenges)
	srv.paymentGate.mu.Unlock()
	if reserved != 0 || pending != 0 {
		t.Fatalf("expected no held pending place after the stalled body timed out, got reservedPending=%d pendingChallenges=%d", reserved, pending)
	}
}

// TestManySlowBodiesLeavePendingPlacesForHonestCallers: the scenario RISK 2
// names directly — many stalled-body connections at once must not prevent
// an honest, bodyless request from getting its own challenge.
func TestManySlowBodiesLeavePendingPlacesForHonestCallers(t *testing.T) {
	prevDeadline := bodyReadDeadline
	bodyReadDeadline = 150 * time.Millisecond
	defer func() { bodyReadDeadline = prevDeadline }()

	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const slowConns = 20
	pipes := make([]*io.PipeWriter, 0, slowConns)
	for i := 0; i < slowConns; i++ {
		pr, pw := io.Pipe()
		pipes = append(pipes, pw)
		req, err := http.NewRequest("POST", ts.URL+"/data", pr)
		if err != nil {
			t.Fatalf("build request %d: %v", i, err)
		}
		go func() {
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	defer func() {
		for _, pw := range pipes {
			pw.Close()
		}
	}()

	// While all slowConns connections are stalled mid-body, an honest
	// bodyless GET for a challenge must still succeed immediately.
	time.Sleep(50 * time.Millisecond)
	ch := getChallenge(t, srv, "GET", "/data?topic=honest:caller")
	if ch.NonceUTXO == nil {
		t.Fatal("expected an honest caller to still get a valid challenge while many bodies stall")
	}
}
