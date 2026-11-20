package routeguard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"golang.org/x/sync/semaphore"
)

// rawPost opens a connection to srv, sends the headers of a POST to /read
// declaring a body of n bytes, then sent, and leaves the connection open.
func rawPost(t *testing.T, srv *httptest.Server, n int, sent []byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "POST /read HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", n)
	if _, err := conn.Write(sent); err != nil {
		t.Fatal(err)
	}
	return conn
}

// trickleTo writes chunk bytes to conn every interval until stop closes or a
// write fails.
func trickleTo(conn net.Conn, chunk int, interval time.Duration, stop chan struct{}) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if _, err := conn.Write(make([]byte, chunk)); err != nil {
				return
			}
		}
	}
}

// nextResult is the server's next ReadBody result, waiting at most limit.
func nextResult(t *testing.T, results chan bodyResult, limit time.Duration) bodyResult {
	t.Helper()
	select {
	case res := <-results:
		return res
	case <-time.After(limit):
		t.Fatalf("ReadBody did not return within %v", limit)
		return bodyResult{}
	}
}

// answerOn reads the server's answer on conn, waiting at most limit, and
// returns its status and the reader holding what follows it.
func answerOn(t *testing.T, conn net.Conn, limit time.Duration) (int, *bufio.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(limit))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no answer on the connection: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, br
}

// closedAfter reports whether the server closed conn after the answer read
// through br, waiting at most a second.
func closedAfter(conn net.Conn, br *bufio.Reader) bool {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := br.ReadByte()
	return errors.Is(err, io.EOF)
}

// awaitPermits waits until requests hold every read permit of g, so they are
// inside ReadBody.
func awaitPermits(t *testing.T, g *Guard) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if !g.read.TryAcquire(1) {
			time.Sleep(100 * time.Millisecond) // and past Begin, into the read
			return
		}
		g.read.Release(1)
	}
	t.Fatal("the request never began")
}

// TestReadBody_HoldsNothingUntilTheFirstByte: a request that has sent only
// its headers, declaring a body over BigBody, holds neither the big-body slot
// nor any heap, so another ticket can take both; once its body arrives it
// takes them and is read.
func TestReadBody_HoldsNothingUntilTheFirstByte(t *testing.T) {
	n := int(2 * BigBody)
	route := Route{MaxBody: 4 * BigBody, Expansion: 1, ReadTimeout: 10 * time.Second}
	g := New(int64(n), 1, 1, testWait)
	g.read = semaphore.NewWeighted(1)
	srv, results := bodyServer(t, g, route, 0, 0)
	conn := rawPost(t, srv, n, nil)
	awaitPermits(t, g)
	other := &Ticket{g: g}
	if err := other.take(t.Context(), slotBig); err != nil {
		t.Fatalf("a request waiting for its first byte holds the big-body slot: %v", err)
	}
	if err := other.Reserve(t.Context(), int64(n)); err != nil {
		t.Fatalf("a request waiting for its first byte holds heap: %v", err)
	}
	other.Close()
	if _, err := conn.Write(make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	res := nextResult(t, results, 10*time.Second)
	if res.err != nil || len(res.body) != n || res.held != int64(n) {
		t.Fatalf("the body once sent: %d bytes holding %d, %v; want %d holding %d", len(res.body), res.held, res.err, n, n)
	}
}

// TestReadBody_IdleBodyIsCutAtTheGrace: a request that sends only its headers
// is cut once bodyread.ReadGrace has passed with no body byte, long before
// its route's read timeout, with ErrBodyTooSlow, which is an ErrReadTimeout.
// It is answered 408, its connection is closed, and its read permit is back.
func TestReadBody_IdleBodyIsCutAtTheGrace(t *testing.T) {
	g := New(1<<20, 1, 1, testWait)
	g.read = semaphore.NewWeighted(1)
	route := Route{MaxBody: 64 << 10, Expansion: 1, ReadTimeout: 10 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	conn := rawPost(t, srv, 1000, nil)
	res := nextResult(t, results, bodyread.ReadGrace+3*time.Second)
	if !errors.Is(res.err, ErrBodyTooSlow) || !errors.Is(res.err, ErrReadTimeout) {
		t.Fatalf("an idle body: %v, want ErrBodyTooSlow wrapping ErrReadTimeout", res.err)
	}
	if res.elapsed < bodyread.ReadGrace || res.elapsed > bodyread.ReadGrace+time.Second {
		t.Fatalf("an idle body was cut after %v, want about %v", res.elapsed, bodyread.ReadGrace)
	}
	code, br := answerOn(t, conn, 3*time.Second)
	if closed := closedAfter(conn, br); code != http.StatusRequestTimeout || !closed {
		t.Fatalf("the idle connection was answered %d, closed %v; want 408 and closed", code, closed)
	}
	t.Logf("idle body cut after %v, answered %d, connection closed", res.elapsed, code)
	tk, err := beginLoopback(g, false)
	if err != nil {
		t.Fatalf("the cut request kept its read permit: %v", err)
	}
	tk.Close()
}

// TestReadBody_StalledBodyIsCutByTheRate: a body that starts and then stalls
// is cut when it falls below MinBodyRate, at ReadGrace plus the time its
// bytes so far earn it, with ErrBodyTooSlow; it is answered 408 on a closed
// connection, and what it reserved is returned.
func TestReadBody_StalledBodyIsCutByTheRate(t *testing.T) {
	const pool = 1 << 20
	g := New(pool, 1, 1, testWait)
	route := Route{MaxBody: 64 << 10, Expansion: 4, ReadTimeout: 10 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	conn := rawPost(t, srv, 50_000, make([]byte, 1000))
	res := nextResult(t, results, bodyread.ReadGrace+3*time.Second)
	if rate := route.MinRate(50_000); rate != MinBodyRate {
		t.Fatalf("a 50,000-byte body's rate is %d, want the floor %d", rate, MinBodyRate)
	}
	due := bodyread.ReadGrace + 1000*time.Second/time.Duration(MinBodyRate)
	if !errors.Is(res.err, ErrBodyTooSlow) {
		t.Fatalf("a stalled body: %v, want ErrBodyTooSlow", res.err)
	}
	if res.elapsed < bodyread.ReadGrace || res.elapsed > due+time.Second {
		t.Fatalf("a stalled body was cut after %v, want about %v", res.elapsed, due)
	}
	code, br := answerOn(t, conn, 3*time.Second)
	if closed := closedAfter(conn, br); code != http.StatusRequestTimeout || !closed {
		t.Fatalf("the stalled connection was answered %d, closed %v; want 408 and closed", code, closed)
	}
	t.Logf("body stalled after 1000 bytes: cut after %v (due %v), answered %d", res.elapsed, due, code)
	tk, _ := beginLoopback(g, false)
	defer tk.Close()
	if err := tk.Reserve(t.Context(), pool); err != nil {
		t.Fatalf("the stalled request's reservation was not returned: %v", err)
	}
}

// TestReadBody_TrickleBelowTheRateIsCut: a body that keeps arriving, but at
// an eighth of MinBodyRate, is cut with ErrBodyTooSlow when its average falls
// short, about ReadGrace / (1 - 1/8) after the read began, long before its
// route's read timeout.
func TestReadBody_TrickleBelowTheRateIsCut(t *testing.T) {
	g := New(1<<20, 1, 1, testWait)
	route := Route{MaxBody: 1 << 20, Expansion: 1, ReadTimeout: 10 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	conn := rawPost(t, srv, 100_000, nil)
	stop := make(chan struct{})
	defer close(stop)
	go trickleTo(conn, int(MinBodyRate/80), 100*time.Millisecond, stop) // 1/8 of the rate
	res := nextResult(t, results, route.ReadTimeout)
	want := bodyread.ReadGrace * 8 / 7
	if !errors.Is(res.err, ErrBodyTooSlow) {
		t.Fatalf("a trickle at an eighth of the rate: %v after %v, want ErrBodyTooSlow", res.err, res.elapsed)
	}
	if res.elapsed < bodyread.ReadGrace || res.elapsed > want+time.Second {
		t.Fatalf("the trickle was cut after %v, want about %v", res.elapsed, want)
	}
	t.Logf("trickle at %d bytes a second cut after %v (expected about %v)", MinBodyRate/8, res.elapsed, want)
}

// TestReadBody_TooSlowNamesTheRateThatApplied (cold review round 4 nit,
// "quote the rate that applied"): ErrBodyTooSlow's text names the exact rate
// the body was held to, not always MinBodyRate, so an operator reading the
// refusal can tell what pace was actually required. A declared body long
// enough that its length, not the floor, sets the rate (paceRate's length
// term, Route.MinRate) is sent under that rate and cut with that number, not
// MinBodyRate's, in its error.
func TestReadBody_TooSlowNamesTheRateThatApplied(t *testing.T) {
	g := New(1<<20, 1, 1, testWait)
	route := Route{MaxBody: 1 << 20, Expansion: 1, ReadTimeout: 3 * time.Second}
	const n = 200_000
	want := route.MinRate(n)
	if want == MinBodyRate {
		t.Fatalf("test setup: %d bytes in %v computed the floor %d, want a length-driven rate above it", n, route.ReadTimeout, MinBodyRate)
	}
	srv, results := bodyServer(t, g, route, 0, 0)
	conn := rawPost(t, srv, n, nil)
	stop := make(chan struct{})
	defer close(stop)
	go trickleTo(conn, int(want/160), 50*time.Millisecond, stop) // 1/8 of the length-driven rate
	res := nextResult(t, results, route.ReadTimeout)
	if !errors.Is(res.err, ErrBodyTooSlow) {
		t.Fatalf("a body held to a length-driven rate: %v, want ErrBodyTooSlow", res.err)
	}
	wantText := fmt.Sprintf("(%d bytes a second)", want)
	if !strings.Contains(res.err.Error(), wantText) {
		t.Fatalf("ErrBodyTooSlow's text %q does not name the rate that applied, want it to contain %q", res.err.Error(), wantText)
	}
}

// TestReadBody_BodyAboveTheRateIsRead: a body that keeps up five times
// MinBodyRate is read in full though it takes longer than ReadGrace.
func TestReadBody_BodyAboveTheRateIsRead(t *testing.T) {
	g := New(1<<20, 1, 1, testWait)
	route := Route{MaxBody: 1 << 20, Expansion: 1, ReadTimeout: 10 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	const chunk, chunks = 4 << 10, 60 // 80 KiB/s for 3 s
	conn := rawPost(t, srv, chunk*chunks, nil)
	stop := make(chan struct{})
	defer close(stop)
	go trickleTo(conn, chunk, 50*time.Millisecond, stop)
	res := nextResult(t, results, route.ReadTimeout)
	if res.err != nil || len(res.body) != chunk*chunks {
		t.Fatalf("a body at 80 KiB/s: %d bytes, %v after %v", len(res.body), res.err, res.elapsed)
	}
	if res.elapsed < bodyread.ReadGrace {
		t.Fatalf("read in %v, under the grace: the test proves nothing", res.elapsed)
	}
	t.Logf("%d bytes at 80 KiB/s read in %v", len(res.body), res.elapsed)
}

// TestReadBody_GuardWaitsDoNotCountAgainstTheSender: a sender whose body is
// all on the wire while the guard keeps it waiting for heap, past its grace,
// is read in full once the heap is free: the guard's own wait is not time the
// sender failed to send.
func TestReadBody_GuardWaitsDoNotCountAgainstTheSender(t *testing.T) {
	const pool = 1 << 20
	g := New(pool, 1, 1, time.Second)
	g.grace = 200 * time.Millisecond
	route := Route{MaxBody: pool, Expansion: 1, ReadTimeout: 10 * time.Second}
	holder, _ := beginLoopback(g, false)
	if err := holder.Reserve(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	srv, results := bodyServer(t, g, route, 0, 0)
	const n = 256 << 10 // past what the server buffers, so reads reach the connection
	conn := rawPost(t, srv, n, nil)
	go func() { _, _ = conn.Write(make([]byte, n)) }()
	time.Sleep(3 * g.grace)
	holder.Close()
	res := nextResult(t, results, 5*time.Second)
	if res.err != nil || len(res.body) != n {
		t.Fatalf("a body kept waiting by the guard past its grace: %d bytes, %v after %v", len(res.body), res.err, res.elapsed)
	}
}

// TestReadBody_RefusedBodyIsAbandoned: a body refused for the heap once it
// has started is read no further. Its client, which has stopped sending, gets
// the 503 at the guard's Wait with Connection: close, and the connection is
// closed, rather than the server waiting to read the rest before it answers.
func TestReadBody_RefusedBodyIsAbandoned(t *testing.T) {
	g := New(1000, 1, 1, testWait)
	holder, _ := beginLoopback(g, false)
	defer holder.Close()
	if err := holder.Reserve(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
	route := Route{MaxBody: 64 << 10, Expansion: 1, ReadTimeout: 10 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	conn := rawPost(t, srv, 1000, make([]byte, 100))
	if res := nextResult(t, results, 5*time.Second); !errors.Is(res.err, ErrBusy) {
		t.Fatalf("a body that cannot reserve: %v, want ErrBusy", res.err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("no answer for a refused body whose sender stopped: %v", err)
	}
	resp.Body.Close()
	if closed := closedAfter(conn, br); resp.StatusCode != http.StatusServiceUnavailable || !resp.Close || !closed {
		t.Fatalf("a refused body: %d, Connection: close %v, closed %v; want 503, close, and the connection closed", resp.StatusCode, resp.Close, closed)
	}
}

// TestReadBody_EmptyBodyHoldsNothing: an empty body, declared or chunked,
// waits for neither the big-body slot nor the heap, and reserves nothing.
func TestReadBody_EmptyBodyHoldsNothing(t *testing.T) {
	g := New(1000, 1, 1, time.Minute)
	holder, _ := beginLoopback(g, false)
	defer holder.Close()
	if err := holder.Reserve(t.Context(), 1000); err != nil {
		t.Fatal(err)
	}
	if err := holder.take(t.Context(), slotBig); err != nil {
		t.Fatal(err)
	}
	route := Route{MaxBody: 4 * BigBody, Expansion: 1, Allowance: 100, ReadTimeout: 5 * time.Second}
	srv, results := bodyServer(t, g, route, 0, 0)
	for name, request := range map[string]string{
		"declared": "POST /read HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
		"chunked":  "POST /read HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	} {
		conn := rawRequest(t, srv, request)
		res := nextResult(t, results, 5*time.Second)
		if res.err != nil || len(res.body) != 0 || res.held != 0 || res.elapsed > time.Second {
			t.Fatalf("%s empty body: %v, %d bytes holding %d after %v", name, res.err, len(res.body), res.held, res.elapsed)
		}
		if code, _ := answerOn(t, conn, 3*time.Second); code != http.StatusOK {
			t.Fatalf("%s empty body answered %d", name, code)
		}
	}
}

// rawRequest opens a connection to srv and sends request as it is.
func rawRequest(t *testing.T, srv *httptest.Server, request string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprint(conn, request)
	return conn
}
