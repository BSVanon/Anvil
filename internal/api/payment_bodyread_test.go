package api

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

// clientResult carries a slow-body request's outcome back to the test
// goroutine — http.Client.Do runs in its own goroutine here so the test can
// inspect server-side state (PaymentGate.reservedPending) while the request
// is still in flight, and t.Fatalf must only ever run on the test goroutine.
type clientResult struct {
	resp *http.Response
	body []byte // the response body, read before it was closed
	err  error
}

// shrinkPaymentBodyGrace runs the test with paymentBodyLimits' grace set to
// grace, the rest of its schedule unchanged.
func shrinkPaymentBodyGrace(t *testing.T, grace time.Duration) {
	t.Helper()
	prev := paymentBodyLimits
	paymentBodyLimits.Grace = grace
	paymentBodyLimits.Timeout = grace + time.Duration(paymentBodyLimits.Max)*time.Second/time.Duration(paymentBodyLimits.MinRate)
	t.Cleanup(func() { paymentBodyLimits = prev })
}

// usePaymentBodyPermits runs the test with a pool of n body-read permits.
func usePaymentBodyPermits(t *testing.T, n int) {
	t.Helper()
	prev := paymentBodyReads
	paymentBodyReads = bodyread.NewPermits(n)
	t.Cleanup(func() { paymentBodyReads = prev })
}

// postStalled sends POST url with a body that delivers first and then stalls
// until the returned writer is closed. The outcome arrives on the channel.
func postStalled(t *testing.T, url string, first []byte) (*io.PipeWriter, <-chan clientResult) {
	t.Helper()
	return postStalledAs(t, url, "", first)
}

// postStalledAs is postStalled from client, an address the request names in
// X-Forwarded-For, which the node takes as the client's address from a
// loopback peer such as this test's (clientIP, auth.go); "" names none.
func postStalledAs(t *testing.T, url, client string, first []byte) (*io.PipeWriter, <-chan clientResult) {
	t.Helper()
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, url, pr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if client != "" {
		req.Header.Set("X-Forwarded-For", client)
	}
	done := make(chan clientResult, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		var body []byte
		if resp != nil {
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		done <- clientResult{resp: resp, body: body, err: err}
	}()
	if len(first) > 0 {
		go func() { _, _ = pw.Write(first) }()
	}
	t.Cleanup(func() { pw.Close() })
	return pw, done
}

func wantStatus(t *testing.T, done <-chan clientResult, want int, within time.Duration) {
	t.Helper()
	select {
	case res := <-done:
		if res.resp == nil || res.resp.StatusCode != want {
			t.Fatalf("got %+v, want status %d", res, want)
		}
	case <-time.After(within):
		t.Fatalf("no response within %v, want status %d", within, want)
	}
}

// TestSlowBodyDoesNotHoldPendingPlace: a request whose body stalls must not
// hold a pending-challenge place (payment_pending.go) while it stalls: the
// body is read before the place is reserved. The connection's read deadline
// then cuts the stalled body at its due time with 408; bodyread's timers
// alone could not, because closing a server request body does not end a
// blocked Read.
func TestSlowBodyDoesNotHoldPendingPlace(t *testing.T) {
	shrinkPaymentBodyGrace(t, 150*time.Millisecond)
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, done := postStalled(t, ts.URL+"/data", nil)
	time.Sleep(50 * time.Millisecond) // the server is now blocked in the body read
	srv.paymentGate.mu.Lock()
	reserved, pending := srv.paymentGate.reservedPending, len(srv.paymentGate.pendingChallenges)
	srv.paymentGate.mu.Unlock()
	if reserved != 0 || pending != 0 {
		t.Fatalf("a stalled body must not hold a pending place while it stalls; got reservedPending=%d pendingChallenges=%d", reserved, pending)
	}
	wantStatus(t, done, http.StatusRequestTimeout, 3*time.Second)
	srv.paymentGate.mu.Lock()
	reserved, pending = srv.paymentGate.reservedPending, len(srv.paymentGate.pendingChallenges)
	srv.paymentGate.mu.Unlock()
	if reserved != 0 || pending != 0 {
		t.Fatalf("no pending place may be held after the stalled body timed out, got reservedPending=%d pendingChallenges=%d", reserved, pending)
	}
}

// TestManySlowBodiesLeavePendingPlacesForHonestCallers: as many stalled-body
// connections as there are pending places must not prevent an honest,
// bodyless request from getting its own challenge. With the place reserved
// before the body read, the stalled bodies would hold every place. Each comes
// from its own client, so no client's share of the body reads
// (payment_bodyshare.go) refuses any of them.
func TestManySlowBodiesLeavePendingPlacesForHonestCallers(t *testing.T) {
	shrinkPaymentBodyGrace(t, 500*time.Millisecond)
	srv := testServerWithPaymentGate(t, 100)
	const slowConns = 20
	srv.paymentGate.maxPending = slowConns
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for i := 0; i < slowConns; i++ {
		postStalledAs(t, ts.URL+"/data", fmt.Sprintf("198.51.100.%d", i+1), nil)
	}
	time.Sleep(100 * time.Millisecond)
	if n := paymentBodyReads.InUse(); n != slowConns {
		t.Fatalf("want all %d stalled bodies in their reads, %d are", slowConns, n)
	}
	ch := getChallenge(t, srv, "GET", "/data?topic=honest:caller")
	if ch.NonceUTXO == nil {
		t.Fatal("an honest caller must still get a valid challenge while many bodies stall")
	}
}

// TestPaymentBodyReadsAreBoundedByPermits: at most paymentBodyReads' permits
// of bodies are buffered at once. A body that finds none free within the
// grace gets 503 with Retry-After, while the bodies holding permits stay in
// their reads.
func TestPaymentBodyReadsAreBoundedByPermits(t *testing.T) {
	shrinkPaymentBodyGrace(t, 300*time.Millisecond)
	usePaymentBodyPermits(t, 2)
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 32 KiB pushes each holder's due time two seconds past the grace.
	first := bytes.Repeat([]byte("a"), 32<<10)
	_, held1 := postStalled(t, ts.URL+"/data", first)
	_, held2 := postStalled(t, ts.URL+"/data", first)
	time.Sleep(100 * time.Millisecond)
	if n := paymentBodyReads.InUse(); n != 2 {
		t.Fatalf("want both permits held, %d are", n)
	}
	_, waiting := postStalled(t, ts.URL+"/data", nil)
	wantStatus(t, waiting, http.StatusServiceUnavailable, time.Second)
	wantStatus(t, held1, http.StatusRequestTimeout, 3*time.Second)
	wantStatus(t, held2, http.StatusRequestTimeout, 3*time.Second)
}

// TestPaymentBodyAtPaceIsReadPastGrace: a body that keeps up the minimum rate
// is read in full however long it takes within the timeout, here several
// times the grace, where a fixed deadline of the grace would have cut it.
func TestPaymentBodyAtPaceIsReadPastGrace(t *testing.T) {
	shrinkPaymentBodyGrace(t, 200*time.Millisecond)
	paymentBodyLimits.MinRate = 16 << 10
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pw, done := postStalled(t, ts.URL+"/data", nil)
	go func() {
		chunk := bytes.Repeat([]byte("b"), 4<<10)
		for i := 0; i < 12; i++ { // 48 KiB at 64 KiB/s, four times the minimum rate: 750 ms
			_, _ = pw.Write(chunk)
			time.Sleep(62 * time.Millisecond)
		}
		pw.Close()
	}()
	wantStatus(t, done, http.StatusPaymentRequired, 5*time.Second)
}

// TestPaymentBodyOverCapGets413: a body over the 1 MiB cap gets 413 Content
// Too Large, on the challenge read and on a proof's live-body read.
func TestPaymentBodyOverCapGets413(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	big := bytes.Repeat([]byte("c"), 1<<20+1)
	send := func(proof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/data", bytes.NewReader(big))
		req.Host = "localhost"
		if proof != "" {
			req.Header.Set(HeaderX402Proof, proof)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := send(""); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("challenge read: got %d %s, want 413", w.Code, w.Body.String())
	}
	ch := getChallenge(t, srv, http.MethodPost, "/data") // bodyless, so the proof binds an empty body
	if w := send(buildProof(t, ch, 100, testPayeeScript(t))); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("proof live-body read: got %d %s, want 413", w.Code, w.Body.String())
	}
}

// TestPaymentBodyCutOffGets400: a body that ends before its declared length,
// a client error rather than a slow one, gets 400.
func TestPaymentBodyCutOffGets400(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST /data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n0123456789")
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a body cut off before its declared length: got %d, want 400", resp.StatusCode)
	}
}

// deadlineRefusingWriter is a ResponseWriter whose connection refuses every
// read deadline with an error other than http.ErrNotSupported.
type deadlineRefusingWriter struct{ *httptest.ResponseRecorder }

func (deadlineRefusingWriter) SetReadDeadline(time.Time) error { return net.ErrClosed }

// TestPaymentBodyDeadlineErrorRefusesRead: when the read deadline cannot be
// set, the body is not read without one; the request gets 500.
func TestPaymentBodyDeadlineErrorRefusesRead(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	req := httptest.NewRequest(http.MethodPost, "/data", strings.NewReader(`{"x":1}`))
	req.Host = "localhost"
	w := deadlineRefusingWriter{httptest.NewRecorder()}
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "read deadline") {
		t.Fatalf("got %d %s, want 500 naming the read deadline", w.Code, w.Body.String())
	}
}
