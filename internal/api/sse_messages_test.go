package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// TestMessageHubFanout verifies new messages are delivered to all subscribers
// matching the recipient+messageBox key, and not to unrelated subscribers.
// Wallets rely on this to receive real-time notifications of messages.
func TestMessageHubFanout(t *testing.T) {
	hub := newMessageHub()

	chA := make(chan *messaging.Message, 4)
	chB := make(chan *messaging.Message, 4)
	chOther := make(chan *messaging.Message, 4)

	unsubA := hub.subscribe("recipient-1", "avos.offer", chA)
	unsubB := hub.subscribe("recipient-1", "avos.offer", chB)
	unsubOther := hub.subscribe("recipient-2", "avos.offer", chOther)
	defer unsubA()
	defer unsubB()
	defer unsubOther()

	hub.notify(&messaging.Message{
		Recipient:  "recipient-1",
		MessageBox: "avos.offer",
		Body:       "hello",
	})

	select {
	case msg := <-chA:
		if msg.Body != "hello" {
			t.Errorf("chA: expected body=hello, got %q", msg.Body)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("chA: subscriber A did not receive message")
	}

	select {
	case msg := <-chB:
		if msg.Body != "hello" {
			t.Errorf("chB: expected body=hello, got %q", msg.Body)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("chB: subscriber B did not receive message")
	}

	select {
	case msg := <-chOther:
		t.Errorf("chOther: should NOT receive message for different recipient, got body=%q", msg.Body)
	case <-time.After(50 * time.Millisecond):
		// expected — different recipient key, no delivery
	}
}

// TestMessageHubNotifyDropsSlowClient verifies the non-blocking drop behavior:
// a subscriber whose channel is full gets skipped, and delivery to other
// subscribers continues. Prevents one stuck client from blocking the whole
// fanout.
func TestMessageHubNotifyDropsSlowClient(t *testing.T) {
	hub := newMessageHub()

	// Unbuffered channel — will block on any send
	slowCh := make(chan *messaging.Message)
	fastCh := make(chan *messaging.Message, 4)

	hub.subscribe("r", "box", slowCh)
	hub.subscribe("r", "box", fastCh)

	// Notify must not block even though slowCh has no reader
	done := make(chan struct{})
	go func() {
		hub.notify(&messaging.Message{Recipient: "r", MessageBox: "box", Body: "delivered"})
		close(done)
	}()

	select {
	case <-done:
		// expected — notify returned despite slow client
	case <-time.After(200 * time.Millisecond):
		t.Fatal("notify blocked on slow client — drop-on-congestion broken")
	}

	// fastCh should have received it
	select {
	case <-fastCh:
		// expected
	case <-time.After(100 * time.Millisecond):
		t.Error("fastCh: did not receive message despite slow client being dropped")
	}
}

// TestMessageHubUnsubscribe verifies that unsubscribing stops delivery to
// that channel.
func TestMessageHubUnsubscribe(t *testing.T) {
	hub := newMessageHub()
	ch := make(chan *messaging.Message, 4)
	unsub := hub.subscribe("r", "box", ch)

	unsub() // stop receiving

	hub.notify(&messaging.Message{Recipient: "r", MessageBox: "box", Body: "should-not-arrive"})

	select {
	case msg := <-ch:
		t.Errorf("received message after unsubscribe: %q", msg.Body)
	case <-time.After(50 * time.Millisecond):
		// expected — unsubscribed, no delivery
	}
}

// TestMessageHubNextIDIsMonotonic verifies event IDs are monotonically
// increasing, as required by SSE Last-Event-ID semantics.
func TestMessageHubNextIDIsMonotonic(t *testing.T) {
	hub := newMessageHub()
	first := hub.nextID()
	second := hub.nextID()
	third := hub.nextID()
	if !(first < second && second < third) {
		t.Errorf("event IDs must be monotonically increasing; got %d, %d, %d", first, second, third)
	}
}

// testServerWithMsgStore returns a server with a real on-disk message store
// attached, so the SSE subscribe handler (which short-circuits to 503 when
// msgStore is nil) can actually exercise its reconnect-comment path.
func testServerWithMsgStore(t *testing.T) *Server {
	t.Helper()
	srv := testServer(t)
	dir := t.TempDir()
	ms, err := messaging.NewStore(dir, 86400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	srv.msgStore = ms
	return srv
}

// runSubscribeForReconnectLine launches the SSE subscribe handler against a
// real httptest server, sends a request with the given Last-Event-ID header,
// reads only the initial flushed reconnect comment, then closes the
// connection. Returns the body bytes read before close.
//
// Using a real http server (not httptest.NewRecorder) so the Flusher and
// request context actually behave the way the handler expects.
func runSubscribeForReconnectLine(t *testing.T, srv *Server, lastID string) string {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	url := ts.URL + "/messages/subscribe?messageBox=testbox&token=" + srv.authToken
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	// Read until the first "\n\n" (end of the initial reconnect comment) or
	// until the context times out. Context cancel closes the body.
	buf := make([]byte, 4096)
	var accumulated []byte
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			accumulated = append(accumulated, buf[:n]...)
			if strings.Contains(string(accumulated), "\n\n") {
				return string(accumulated)
			}
		}
		if err != nil {
			return string(accumulated)
		}
	}
}

// TestSSEReconnectEchoesParsedIntLastEventID — the sanitization path for a
// valid numeric Last-Event-ID: we echo the parsed int to help operators
// correlate reconnect gaps in logs.
func TestSSEReconnectEchoesParsedIntLastEventID(t *testing.T) {
	srv := testServerWithMsgStore(t)
	got := runSubscribeForReconnectLine(t, srv, "42")
	if !strings.Contains(got, ": reconnected after id 42") {
		t.Errorf("expected parsed int in reconnect comment, got:\n%s", got)
	}
}

// TestSSEReconnectSanitizesMalformedLastEventID — the regression test for the
// 2026-04-17 BUG_HUNTS G705 finding. A malformed Last-Event-ID header (with
// embedded newlines that would inject a fake SSE data: frame, or arbitrary
// non-numeric content) must NOT be echoed verbatim into the stream. The
// handler emits a generic reconnect notice and drops the value.
func TestSSEReconnectSanitizesMalformedLastEventID(t *testing.T) {
	srv := testServerWithMsgStore(t)

	// Non-numeric value — must be dropped, not echoed.
	got := runSubscribeForReconnectLine(t, srv, "not-a-number-surprise")
	if strings.Contains(got, "not-a-number-surprise") {
		t.Errorf("malformed Last-Event-ID MUST NOT appear in response; got:\n%s", got)
	}
	if !strings.Contains(got, ": reconnected — use POST /listMessages to backfill") {
		t.Errorf("expected generic reconnect notice for malformed header; got:\n%s", got)
	}
}

// TestSSEReconnectSkipsCommentWhenNoLastEventID verifies that without a
// Last-Event-ID header, no reconnect comment is emitted at all.
func TestSSEReconnectSkipsCommentWhenNoLastEventID(t *testing.T) {
	srv := testServerWithMsgStore(t)
	got := runSubscribeForReconnectLine(t, srv, "")
	if strings.Contains(got, "reconnected") {
		t.Errorf("fresh connection (no Last-Event-ID) should not emit reconnect comment; got:\n%s", got)
	}
}
