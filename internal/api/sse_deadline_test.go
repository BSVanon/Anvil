package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/messaging"
)

// --- RISK 1 real-stalled-socket tests ---
//
// A fake ResponseWriter (streamTestResponse, sse_caps_test.go) cannot
// reproduce the hazard this guards against: Write/Flush only actually
// blocks when the OS send buffer is full and the peer's advertised TCP
// window is zero, which requires a real socket whose reader has stopped
// draining it. These tests dial a raw net.Conn against a real
// httptest.Server, send a bare HTTP request, and then never read the
// response — exactly the "client opened the connection and stopped
// reading" scenario — and prove the handler still returns, releasing its
// stream-cap slot and its goroutine, within roughly sseWriteDeadline plus
// one heartbeat interval. Both ends' socket buffers are shrunk so a modest
// burst of small SSE frames (not megabytes) is enough to close the window.

// sndbufShrinkingListener wraps every accepted connection's SO_SNDBUF down
// to a few KB, so the server side fills its own send buffer quickly once
// the peer stops reading, instead of depending on a large (and
// platform-variable) default.
type sndbufShrinkingListener struct{ net.Listener }

func (l *sndbufShrinkingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(2048)
	}
	return c, nil
}

// stalledSSEServer starts a real httptest.Server over h whose accepted
// connections have a shrunk send buffer, and returns a "released" check
// driven by the connection's own state rather than process-wide goroutine
// counts (too noisy — unrelated goroutines come and go). ConnState reports
// StateIdle (or StateClosed/StateHijacked) exactly when net/http's
// connection-serving loop regains control after a handler returns — this
// is literally "the handler for this request is done," independent of
// whether the handler happened to be blocked on a write beforehand.
func stalledSSEServer(t *testing.T, h http.Handler) (ts *httptest.Server, released func() bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var idle atomic.Bool
	ts = httptest.NewUnstartedServer(h)
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateIdle, http.StateClosed, http.StateHijacked:
			idle.Store(true)
		case http.StateActive:
			idle.Store(false)
		}
	}
	_ = ts.Listener.Close()
	ts.Listener = &sndbufShrinkingListener{ln}
	ts.Start()
	t.Cleanup(ts.Close)
	return ts, idle.Load
}

// dialStalledClient opens a raw TCP connection to ts, shrinks its own
// receive buffer (so it advertises a small TCP window), sends a bare GET
// request for path, and then — deliberately — never reads the response.
func dialStalledClient(t *testing.T, ts *httptest.Server, path string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(2048)
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: stalled.test\r\nX-Anvil-Auth: test-token\r\nConnection: keep-alive\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	return conn
	// deliberately never read from conn
}

// driveUntilReleased calls publish repeatedly (small sleep between calls)
// until released reports true, or fails the test once ceiling elapses.
// Driving publishes — rather than hardcoding an iteration count — adapts to
// whatever OS socket-buffer sizing is actually in effect, and the bounded
// ceiling is what makes the mutation check ("remove the deadline") fail
// cleanly instead of hanging: with no deadline, released() never becomes
// true and this reports a clean test failure once ceiling passes, while the
// now-permanently-blocked handler goroutine is left behind in the test
// binary (harmless until process exit).
func driveUntilReleased(t *testing.T, ceiling time.Duration, publish func(), released func() bool) {
	t.Helper()
	deadline := time.Now().Add(ceiling)
	for time.Now().Before(deadline) {
		if released() {
			return
		}
		publish()
		time.Sleep(time.Millisecond)
	}
	if !released() {
		t.Fatalf("stream was not released within %s of a stalled socket", ceiling)
	}
}

// shrinkSSEWriteDeadline sets sseWriteDeadline to d for the duration of the
// test (restored via t.Cleanup) — a var, not a const, exactly so tests can
// do this instead of waiting out the real default.
func shrinkSSEWriteDeadline(t *testing.T, d time.Duration) {
	t.Helper()
	old := sseWriteDeadline
	sseWriteDeadline = d
	t.Cleanup(func() { sseWriteDeadline = old })
}

func TestStalledSocketReleasesChaintracksV2TipStream(t *testing.T) {
	shrinkSSEWriteDeadline(t, 80*time.Millisecond)
	old := sseHeartbeatInterval
	sseHeartbeatInterval = 10 * time.Millisecond
	t.Cleanup(func() { sseHeartbeatInterval = old })
	setChaintracksSSETestLimits(t, 10, 10)

	srv := testServer(t)
	ts, released := stalledSSEServer(t, srv.Handler())

	dialStalledClient(t, ts, "/chaintracks/v2/tip/stream")
	time.Sleep(30 * time.Millisecond) // let the handler subscribe before driving

	driveUntilReleased(t, 5*time.Second, func() { extendChaintracksChain(t, srv, 1) }, released)

	liveChaintracksStreams.Lock()
	total, byClient := liveChaintracksStreams.total, len(liveChaintracksStreams.byClient)
	liveChaintracksStreams.Unlock()
	if total != 0 || byClient != 0 {
		t.Fatalf("chaintracks v2 stream slot not released: total=%d distinct-clients=%d", total, byClient)
	}
}

func TestStalledSocketReleasesDataSubscribe(t *testing.T) {
	shrinkSSEWriteDeadline(t, 80*time.Millisecond)

	srv := testServer(t)
	ts, released := stalledSSEServer(t, srv.Handler())

	dialStalledClient(t, ts, "/data/subscribe?topic=stalltopic")
	time.Sleep(30 * time.Millisecond)

	env := &envelope.Envelope{Type: "data", Topic: "stalltopic", Payload: `{"x":1}`}
	driveUntilReleased(t, 5*time.Second, func() { srv.NotifyEnvelope(env) }, released)
}

func TestStalledSocketReleasesMessageboxSubscribe(t *testing.T) {
	shrinkSSEWriteDeadline(t, 80*time.Millisecond)
	old := sseHeartbeatInterval
	sseHeartbeatInterval = 10 * time.Millisecond
	t.Cleanup(func() { sseHeartbeatInterval = old })
	setSSETestLimits(t, 10, 10, 10)

	srv := testServerWithMsgStore(t)
	ts, released := stalledSSEServer(t, srv.Handler())

	path := "/messages/subscribe?messageBox=stallbox&recipient=stallrecipient"
	dialStalledClient(t, ts, path)
	time.Sleep(30 * time.Millisecond)

	msg := &messaging.StoredMessage{Message: messaging.Message{
		Recipient: "stallrecipient", MessageBox: "stallbox", Body: "x",
	}}
	driveUntilReleased(t, 5*time.Second, func() { srv.NotifyMessage(msg) }, released)

	liveMessageStreamCounts.Lock()
	total, byClient := liveMessageStreamCounts.total, len(liveMessageStreamCounts.byClient)
	liveMessageStreamCounts.Unlock()
	if total != 0 || byClient != 0 {
		t.Fatalf("messagebox stream slot not released: total=%d distinct-clients=%d", total, byClient)
	}
}

func TestStalledSocketReleasesMempoolWatchSubscribe(t *testing.T) {
	shrinkSSEWriteDeadline(t, 80*time.Millisecond)

	srv := testServerWithWatcher(t)
	const addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	if err := srv.watcher.Add(addr); err != nil {
		t.Fatal(err)
	}
	h160 := getHash160ForAddress(t, srv.watcher, addr)

	ts, released := stalledSSEServer(t, srv.Handler())

	dialStalledClient(t, ts, "/mempool/watch/subscribe?address="+addr)
	time.Sleep(30 * time.Millisecond)

	var n int64
	driveUntilReleased(t, 5*time.Second, func() {
		n++
		// Distinct satoshis per call so each CheckTx sees a genuinely new
		// tx (distinct hash), never a duplicate the watcher could
		// legitimately skip re-notifying for.
		txHash, raw := buildTestP2PKHTx(h160, 1000+n)
		srv.watcher.CheckTx(txHash, raw)
	}, released)
}
