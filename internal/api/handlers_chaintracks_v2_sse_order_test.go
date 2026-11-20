package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
)

// --- Chaintracks v2 SSE: subscribe ordering and latest-tip semantics ---
//
// These tests prove two things the content-level tests in
// handlers_chaintracks_v2_sse_test.go cannot: that both handlers register
// their feed subscription before writing anything (so a publish landing in
// that gap is never lost), and that a tip notification always resolves to
// the store's current tip rather than whatever value happened to still be
// sitting in the notification channel. Both are proved deterministically —
// no sleeps, and no timeout stands in for an assertion.

// chaintracksOrderLog is a mutex-guarded, append-only record of handler
// lifecycle events, shared between a subscribeOrderStore and an
// orderRecorder so a test can compare when each happened without any
// timing.
type chaintracksOrderLog struct {
	mu     sync.Mutex
	events []string
}

func (l *chaintracksOrderLog) append(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *chaintracksOrderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

// firstIndex returns the index of event's first occurrence, or -1.
func (l *chaintracksOrderLog) firstIndex(event string) int {
	for i, e := range l.snapshot() {
		if e == event {
			return i
		}
	}
	return -1
}

// subscribeOrderStore wraps a headerStore so SubscribeTip/SubscribeReorg
// record a "subscribe" event before forwarding to the real store.
type subscribeOrderStore struct {
	headerStore
	log *chaintracksOrderLog
}

func (s *subscribeOrderStore) SubscribeTip(ch chan uint32) func() {
	s.log.append("subscribe")
	return s.headerStore.SubscribeTip(ch)
}

func (s *subscribeOrderStore) SubscribeReorg(ch chan headers.ReorgNotice) func() {
	s.log.append("subscribe")
	return s.headerStore.SubscribeReorg(ch)
}

// orderRecorder is a minimal http.ResponseWriter/http.Flusher that records
// a "write"/"flush" event on the same log a subscribeOrderStore uses. Its
// onFlush callback, if set, runs once, right after the first Flush — the
// ordering tests use it to cancel the request context so the handler
// returns on its own once that first event is out, with nothing timed.
type orderRecorder struct {
	log     *chaintracksOrderLog
	header  http.Header
	onFlush func()
	once    sync.Once
}

func newOrderRecorder(log *chaintracksOrderLog, onFlush func()) *orderRecorder {
	return &orderRecorder{log: log, header: make(http.Header), onFlush: onFlush}
}

func (w *orderRecorder) Header() http.Header { return w.header }

func (w *orderRecorder) WriteHeader(int) {}

func (w *orderRecorder) Write(p []byte) (int, error) {
	w.log.append("write")
	return len(p), nil
}

func (w *orderRecorder) Flush() {
	w.log.append("flush")
	if w.onFlush != nil {
		w.once.Do(w.onFlush)
	}
}

// runOrderedHandler drives handler with a subscribeOrderStore-wrapped store
// and an orderRecorder that cancels the request context after the first
// Flush, then waits for handler to return. The wait is bounded only as a
// safety net against a genuine hang — the handler is expected to return
// almost immediately once its context is cancelled, so the bound proves
// nothing by itself; the returned log's contents are the proof.
func runOrderedHandler(t *testing.T, srv *Server, path string, handler func(http.ResponseWriter, *http.Request)) *chaintracksOrderLog {
	t.Helper()
	log := &chaintracksOrderLog{}
	srv.headerStore = &subscribeOrderStore{headerStore: srv.headerStore, log: log}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	w := newOrderRecorder(log, cancel)

	done := make(chan struct{})
	go func() {
		handler(w, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("handler did not return after its first event")
	}
	return log
}

// assertSubscribeBeforeFirstEvent fails unless "subscribe" precedes the
// earliest of "write"/"flush" in log.
func assertSubscribeBeforeFirstEvent(t *testing.T, log *chaintracksOrderLog) {
	t.Helper()
	events := log.snapshot()
	subIdx := log.firstIndex("subscribe")
	if subIdx == -1 {
		t.Fatalf("no subscribe event recorded: %v", events)
	}
	firstEvent := -1
	for _, name := range []string{"write", "flush"} {
		if idx := log.firstIndex(name); idx != -1 && (firstEvent == -1 || idx < firstEvent) {
			firstEvent = idx
		}
	}
	if firstEvent == -1 {
		t.Fatalf("no write or flush event recorded: %v", events)
	}
	if subIdx > firstEvent {
		t.Fatalf("subscribe at index %d came after the first write/flush at index %d: %v", subIdx, firstEvent, events)
	}
}

// TestChaintracksV2TipStreamSubscribesBeforeFirstWrite proves
// handleChaintracksV2TipStream registers its tip subscription before its
// initial write, so a tip published in that gap is never lost.
func TestChaintracksV2TipStreamSubscribesBeforeFirstWrite(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 1)
	log := runOrderedHandler(t, srv, "/chaintracks/v2/tip/stream", srv.handleChaintracksV2TipStream)
	assertSubscribeBeforeFirstEvent(t, log)
}

// TestChaintracksV2ReorgStreamSubscribesBeforeFirstFlush proves
// handleChaintracksV2ReorgStream registers its reorg subscription before
// its header flush, so a reorg published in that gap is never lost.
func TestChaintracksV2ReorgStreamSubscribesBeforeFirstFlush(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 1)
	log := runOrderedHandler(t, srv, "/chaintracks/v2/reorg/stream", srv.handleChaintracksV2ReorgStream)
	assertSubscribeBeforeFirstEvent(t, log)
}

// chaintracksV2TipFrames decodes every "data: " SSE line in body, in order,
// as a chaintracksV2Header — body is an httptest.ResponseRecorder's
// accumulated writes, which concatenates every write rather than keeping
// them separate the way orderRecorder does.
func chaintracksV2TipFrames(t *testing.T, body string) []chaintracksV2Header {
	t.Helper()
	var out []chaintracksV2Header
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var hdr chaintracksV2Header
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &hdr); err != nil {
			t.Fatalf("decode frame %q: %v", line, err)
		}
		out = append(out, hdr)
	}
	return out
}

// TestChaintracksV2TipEventSkipsUnchangedNotification proves a notification
// that resolves to the tip this stream already sent — the initial event
// included — produces no second frame.
func TestChaintracksV2TipEventSkipsUnchangedNotification(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 1)

	ch := make(chan uint32, 1)
	unsub := srv.headerStore.SubscribeTip(ch)
	defer unsub()

	w := httptest.NewRecorder()
	var lastSent chaintracksTipDedup
	if err := srv.writeChaintracksV2TipEvent(w, &lastSent); err != nil {
		t.Fatalf("initial send: %v", err)
	}
	if frames := chaintracksV2TipFrames(t, w.Body.String()); len(frames) != 1 {
		t.Fatalf("initial send produced %d frames, want 1", len(frames))
	}

	// A notification that resolves to the tip this stream already sent
	// must not produce a second frame.
	ch <- srv.headerStore.Tip()
	<-ch
	if err := srv.writeChaintracksV2TipEvent(w, &lastSent); err != nil {
		t.Fatalf("repeat send: %v", err)
	}
	if frames := chaintracksV2TipFrames(t, w.Body.String()); len(frames) != 1 {
		t.Fatalf("unchanged tip produced %d frames total, want still 1", len(frames))
	}
}

// TestChaintracksV2TipEventSendsLatestAfterDroppedNotification proves that
// even when the feed's non-blocking publish (feed.go) drops a notification,
// the next send still carries the store's actual current tip rather than a
// stale or intermediate one.
func TestChaintracksV2TipEventSendsLatestAfterDroppedNotification(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 1)

	ch := make(chan uint32, 1)
	unsub := srv.headerStore.SubscribeTip(ch)
	defer unsub()

	w := httptest.NewRecorder()
	var lastSent chaintracksTipDedup
	if err := srv.writeChaintracksV2TipEvent(w, &lastSent); err != nil {
		t.Fatalf("initial send: %v", err)
	}

	// Two advances without draining ch in between: the first publish fills
	// the 1-slot channel, so the feed's non-blocking send (feed.go) drops
	// the second.
	extendChaintracksChain(t, srv, 1) // tip 1 -> 2, publishes 2
	extendChaintracksChain(t, srv, 1) // tip 2 -> 3, publish of 3 is dropped
	if notified := <-ch; notified != 2 {
		t.Fatalf("expected the first publish (2) still queued and the second dropped, got %d", notified)
	}

	if err := srv.writeChaintracksV2TipEvent(w, &lastSent); err != nil {
		t.Fatalf("post-notification send: %v", err)
	}
	frames := chaintracksV2TipFrames(t, w.Body.String())
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames total, got %d", len(frames))
	}
	if frames[1].Height != 3 {
		t.Fatalf("second frame height = %d, want 3 (the current tip, not the stale notified height 2)", frames[1].Height)
	}
}
