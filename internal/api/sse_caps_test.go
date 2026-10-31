package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type streamTestResponse struct {
	header  http.Header
	started chan int
	once    sync.Once
	mu      sync.Mutex
	code    int
	body    bytes.Buffer
}

func newStreamTestResponse() *streamTestResponse {
	return &streamTestResponse{header: make(http.Header), started: make(chan int, 1)}
}

func (w *streamTestResponse) Header() http.Header { return w.header }

func (w *streamTestResponse) WriteHeader(code int) {
	w.mu.Lock()
	w.code = code
	w.mu.Unlock()
	w.once.Do(func() { w.started <- code })
}

func (w *streamTestResponse) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.code == 0 {
		w.code = http.StatusOK
		w.once.Do(func() { w.started <- http.StatusOK })
	}
	return w.body.Write(p)
}

func (w *streamTestResponse) Flush() {}

func (w *streamTestResponse) result() (int, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.code, w.body.String()
}

func resetMessageStreamCounts() {
	liveMessageStreamCounts.Lock()
	liveMessageStreamCounts.byClient = make(map[string]int)
	liveMessageStreamCounts.byIdentity = make(map[string]int)
	liveMessageStreamCounts.total = 0
	liveMessageStreamCounts.Unlock()
}

func setSSETestLimits(t *testing.T, client, identity, global int) {
	t.Helper()
	oldClient, oldIdentity, oldGlobal := sseMaxStreamsPerClientKey, sseMaxStreamsPerIdentity, sseMaxStreamsNodeWide
	resetMessageStreamCounts()
	sseMaxStreamsPerClientKey, sseMaxStreamsPerIdentity, sseMaxStreamsNodeWide = client, identity, global
	t.Cleanup(func() {
		resetMessageStreamCounts()
		sseMaxStreamsPerClientKey, sseMaxStreamsPerIdentity, sseMaxStreamsNodeWide = oldClient, oldIdentity, oldGlobal
	})
}

type runningTestStream struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func startTestStream(t *testing.T, srv *Server, remoteAddr string) *runningTestStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/messages/subscribe?messageBox=box&token="+srv.authToken, nil).WithContext(ctx)
	req.RemoteAddr = remoteAddr
	w := newStreamTestResponse()
	done := make(chan struct{})
	go func() {
		srv.handleMessageSubscribe(w, req)
		close(done)
	}()
	select {
	case code := <-w.started:
		if code != http.StatusOK {
			cancel()
			t.Fatalf("stream status = %d, want 200", code)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("stream did not start")
	}
	return &runningTestStream{cancel: cancel, done: done}
}

func stopTestStream(t *testing.T, stream *runningTestStream) {
	t.Helper()
	stream.cancel()
	select {
	case <-stream.done:
	case <-time.After(time.Second):
		t.Fatal("stream did not disconnect")
	}
}

func rejectedTestStream(t *testing.T, srv *Server, remoteAddr string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/messages/subscribe?messageBox=box&token="+srv.authToken, nil)
	req.RemoteAddr = remoteAddr
	w := newStreamTestResponse()
	srv.handleMessageSubscribe(w, req)
	code, body := w.result()
	if code != http.StatusTooManyRequests || body != messageboxRateLimitBody {
		t.Fatalf("limited stream = %d %q", code, body)
	}
	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestSSEConcurrentStreamCapsReleaseOnDisconnect(t *testing.T) {
	tests := []struct {
		name                     string
		client, identity, global int
		firstAddr, nextAddr      string
	}{
		{name: "per client key", client: 1, identity: 10, global: 10, firstAddr: "203.0.113.1:1", nextAddr: "203.0.113.1:2"},
		{name: "per identity", client: 10, identity: 1, global: 10, firstAddr: "203.0.113.1:1", nextAddr: "203.0.113.2:1"},
		{name: "node wide", client: 10, identity: 10, global: 1, firstAddr: "203.0.113.1:1", nextAddr: "203.0.113.2:1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setSSETestLimits(t, tc.client, tc.identity, tc.global)
			srv := testServerWithMsgStore(t)
			first := startTestStream(t, srv, tc.firstAddr)
			rejectedTestStream(t, srv, tc.nextAddr)
			stopTestStream(t, first)
			admitted := startTestStream(t, srv, tc.nextAddr)
			stopTestStream(t, admitted)
		})
	}
}
