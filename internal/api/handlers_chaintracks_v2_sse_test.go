package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
	p2pchainhash "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

// --- Chaintracks v2 SSE tests: tip/stream and reorg/stream ---
//
// The initial-event / new-tip / reorg / heartbeat tests drive a real
// httptest.Server and read the response body with blocking Read calls
// (mirroring sse_messages_test.go's runSubscribeForReconnectLine), rather
// than polling a recorder — the same split this package already uses
// between its content-sensitive SSE tests (real server) and its cap
// lifecycle tests (direct handler calls via streamTestResponse, see
// sse_caps_test.go).

// interopReadSSEDataLine ports the scan loop inside the canonical client's
// readSSE (client.go:261-301, identical in readReorgSSE at :316-359): read
// lines one at a time, silently skip anything that isn't a "data: "-prefixed
// line (so the ": ping" heartbeat comment and blank lines are ignored
// exactly as a real consumer would ignore them), then JSON-decode the first
// data line found into v. Returns false once the reader is exhausted (the
// canonical loop's ctx.Done()/err path) before any data line appeared.
func interopReadSSEDataLine(r *bufio.Reader, v interface{}) (ok bool, err error) {
	for {
		line, rerr := r.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "data: ") {
			data := strings.TrimPrefix(trimmed, "data: ")
			if data != "" {
				if jsonErr := json.Unmarshal([]byte(data), v); jsonErr != nil {
					return false, jsonErr
				}
				return true, nil
			}
		}
		if rerr != nil {
			return false, nil
		}
	}
}

// chaintracksStreamGet issues a GET against path on a real httptest.Server
// wrapping srv, returning the live response for the caller to read
// incrementally. The context (and so the connection) is cancelled by
// t.Cleanup.
func chaintracksStreamGet(t *testing.T, srv *Server, path string) *http.Response {
	t.Helper()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, "GET", ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// extendChaintracksChain appends n more synthetic headers right after the
// current tip (distinct from addServerTestChain, server_test.go:190-206,
// which always starts fresh from genesis), so a test can observe a tip
// change on an already-running stream.
func extendChaintracksChain(t *testing.T, srv *Server, n int) uint32 {
	t.Helper()
	from := srv.headerStore.Tip()
	prevHash, err := srv.headerStore.HashAtHeight(from)
	if err != nil {
		t.Fatal(err)
	}
	merkle, err := p2pchainhash.NewHashFromStr("abcdef0000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	hdrs := make([]*wire.BlockHeader, 0, n)
	for i := 0; i < n; i++ {
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(1000+i))
		hdrs = append(hdrs, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}
	if err := srv.headerStore.AddHeaders(from+1, hdrs); err != nil {
		t.Fatal(err)
	}
	return from + uint32(n)
}

// buildChaintracksFork returns n headers forking from the header at
// forkHeight, carrying a distinct merkle salt/nonce range from
// addServerTestChain/extendChaintracksChain so the two chains are genuinely
// different headers. Mirrors internal/headers/reorg_test.go's buildChain
// (unexported, different package).
func buildChaintracksFork(t *testing.T, srv *Server, forkHeight uint32, n int) []*wire.BlockHeader {
	t.Helper()
	forkPoint, err := srv.headerStore.HashAtHeight(forkHeight)
	if err != nil {
		t.Fatal(err)
	}
	merkle, err := p2pchainhash.NewHashFromStr("fedcba0000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	hdrs := make([]*wire.BlockHeader, 0, n)
	prev := forkPoint
	for i := 0; i < n; i++ {
		hdr := wire.NewBlockHeader(1, prev, merkle, 0x1d00ffff, uint32(9000+i))
		hdrs = append(hdrs, hdr)
		h := hdr.BlockHash()
		prev = &h
	}
	return hdrs
}

// TestChaintracksV2TipStreamInitialEvent proves tip/stream sends the current
// tip immediately on connect, canonical: routes/fiber/routes.go:343-396
// handleTipStream's first write.
func TestChaintracksV2TipStreamInitialEvent(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 3)

	resp := chaintracksStreamGet(t, srv, "/chaintracks/v2/tip/stream")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", got)
	}
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Fatalf("X-Accel-Buffering = %q, want no", got)
	}

	var hdr chaintracksV2Header
	r := bufio.NewReader(resp.Body)
	ok, err := interopReadSSEDataLine(r, &hdr)
	if err != nil {
		t.Fatalf("decode initial SSE frame: %v", err)
	}
	if !ok {
		t.Fatal("stream closed before an initial data line arrived")
	}
	if hdr.Height != 3 {
		t.Fatalf("initial event height = %d, want 3", hdr.Height)
	}
	want, err := srv.headerStore.HashAtHeight(3)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Hash != want.String() {
		t.Fatalf("initial event hash = %s, want %s", hdr.Hash, want.String())
	}
}

// TestChaintracksV2TipStreamNewTipEvent proves a forward append (not just
// the initial send) reaches an already-connected stream, via
// internal/headers.Store.AddHeaders' s.tipFeed.publish(newTip)
// (internal/headers/store.go).
func TestChaintracksV2TipStreamNewTipEvent(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 2)

	resp := chaintracksStreamGet(t, srv, "/chaintracks/v2/tip/stream")
	r := bufio.NewReader(resp.Body)

	var first chaintracksV2Header
	if ok, err := interopReadSSEDataLine(r, &first); err != nil || !ok {
		t.Fatalf("initial event: ok=%v err=%v", ok, err)
	}
	if first.Height != 2 {
		t.Fatalf("initial height = %d, want 2", first.Height)
	}

	extendChaintracksChain(t, srv, 1)

	var next chaintracksV2Header
	ok, err := interopReadSSEDataLine(r, &next)
	if err != nil {
		t.Fatalf("decode new-tip SSE frame: %v", err)
	}
	if !ok {
		t.Fatal("stream closed before the new-tip event arrived")
	}
	if next.Height != 3 {
		t.Fatalf("new-tip event height = %d, want 3", next.Height)
	}
}

// TestChaintracksV2ReorgStreamEvent proves a below-tip reorg reaches
// reorg/stream in the canonical ReorgEvent shape (chaintracks/types.go
// :41-57: orphanedHashes, commonAncestor, newTip, depth), and that no
// initial event is sent on connect (canonical: routes.go:398-445
// handleReorgStream has no first write, unlike handleTipStream).
func TestChaintracksV2ReorgStreamEvent(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	resp := chaintracksStreamGet(t, srv, "/chaintracks/v2/reorg/stream")
	r := bufio.NewReader(resp.Body)

	// Fork at height 3, extending 4 blocks (to height 7) — heavier than the
	// 2 blocks (heights 4,5) it discards, so ReorgTo adopts it. ReorgTo is
	// not part of the api.headerStore interface (no production handler
	// drives a reorg directly), so the test reaches the concrete store.
	hs, ok := srv.headerStore.(*headers.Store)
	if !ok {
		t.Fatal("expected a concrete *headers.Store in tests")
	}
	fork := buildChaintracksFork(t, srv, 3, 4)
	adopted, forkHeight, err := hs.ReorgTo(fork)
	if err != nil {
		t.Fatalf("ReorgTo: %v", err)
	}
	if !adopted || forkHeight != 3 {
		t.Fatalf("expected the fork adopted at height 3, got adopted=%v forkHeight=%d", adopted, forkHeight)
	}

	var event map[string]interface{}
	gotFrame, err := interopReadSSEDataLine(r, &event)
	if err != nil {
		t.Fatalf("decode reorg SSE frame: %v", err)
	}
	if !gotFrame {
		t.Fatal("stream closed before the reorg event arrived")
	}

	orphaned, _ := event["orphanedHashes"].([]interface{})
	if len(orphaned) != 2 {
		t.Fatalf("orphanedHashes length = %d, want 2 (heights 4,5 discarded)", len(orphaned))
	}
	if depth, _ := event["depth"].(float64); depth != 2 {
		t.Fatalf("depth = %v, want 2", event["depth"])
	}
	ancestor, _ := event["commonAncestor"].(map[string]interface{})
	if ancestor == nil || ancestor["height"].(float64) != 3 {
		t.Fatalf("commonAncestor = %#v, want height 3", event["commonAncestor"])
	}
	newTip, _ := event["newTip"].(map[string]interface{})
	if newTip == nil || newTip["height"].(float64) != 7 {
		t.Fatalf("newTip = %#v, want height 7", event["newTip"])
	}
}

// TestChaintracksV2StreamHeartbeat proves an idle stream (no new tip) still
// emits ": ping" comment lines, reusing Anvil's existing messagebox SSE
// heartbeat convention (sse_messages.go's sseHeartbeatInterval), shortened
// here the same way TestSSEHeartbeat (sse_messages_test.go) shortens it.
func TestChaintracksV2StreamHeartbeat(t *testing.T) {
	old := sseHeartbeatInterval
	sseHeartbeatInterval = 20 * time.Millisecond
	defer func() { sseHeartbeatInterval = old }()

	srv := testServer(t)
	addServerTestChain(t, srv, 1)

	resp := chaintracksStreamGet(t, srv, "/chaintracks/v2/tip/stream")
	r := bufio.NewReader(resp.Body)

	// First line is the initial tip's "data: " frame; discard it.
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(strings.TrimSpace(line), "data: ") {
		t.Fatalf("expected initial data line, got %q (err=%v)", line, err)
	}
	if _, err := r.ReadString('\n'); err != nil { // blank line ending the frame
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		line, err = r.ReadString('\n')
		if strings.TrimSpace(line) == ": ping" {
			return
		}
		if err != nil {
			t.Fatalf("stream ended before a heartbeat arrived: %v", err)
		}
	}
	t.Fatal("no \": ping\" heartbeat observed within 2s of a 20ms interval")
}

// --- Concurrent-stream cap lifecycle: direct handler calls, mirroring
// sse_caps_test.go's TestSSEConcurrentStreamCapsReleaseOnDisconnect for the
// messagebox streams. Only two cap axes exist here (client, global) — there
// is no per-identity axis on a no-login route.

func resetChaintracksStreamCounts() {
	liveChaintracksStreams.Lock()
	liveChaintracksStreams.byClient = make(map[string]int)
	liveChaintracksStreams.total = 0
	liveChaintracksStreams.Unlock()
}

func setChaintracksSSETestLimits(t *testing.T, client, global int) {
	t.Helper()
	oldClient, oldGlobal := chaintracksSSEMaxPerClient, chaintracksSSEMaxGlobal
	resetChaintracksStreamCounts()
	chaintracksSSEMaxPerClient, chaintracksSSEMaxGlobal = client, global
	t.Cleanup(func() {
		resetChaintracksStreamCounts()
		chaintracksSSEMaxPerClient, chaintracksSSEMaxGlobal = oldClient, oldGlobal
	})
}

func startChaintracksTipStream(t *testing.T, srv *Server, remoteAddr string) *runningTestStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/chaintracks/v2/tip/stream", nil).WithContext(ctx)
	req.RemoteAddr = remoteAddr
	w := newStreamTestResponse()
	done := make(chan struct{})
	go func() {
		srv.handleChaintracksV2TipStream(w, req)
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

func rejectedChaintracksTipStream(t *testing.T, srv *Server, remoteAddr string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/chaintracks/v2/tip/stream", nil)
	req.RemoteAddr = remoteAddr
	w := newStreamTestResponse()
	srv.handleChaintracksV2TipStream(w, req)
	code, body := w.result()
	if code != http.StatusTooManyRequests {
		t.Fatalf("limited stream status = %d, want 429 (body=%q)", code, body)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(body), &parsed); err != nil || parsed["error"] == "" {
		t.Fatalf("limited stream body = %q, want a bare {\"error\":...}", body)
	}
	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestChaintracksV2StreamConcurrentCapsReleaseOnDisconnect(t *testing.T) {
	tests := []struct {
		name                string
		client, global      int
		firstAddr, nextAddr string
	}{
		{name: "per client key", client: 1, global: 10, firstAddr: "203.0.113.1:1", nextAddr: "203.0.113.1:2"},
		{name: "node wide", client: 10, global: 1, firstAddr: "203.0.113.1:1", nextAddr: "203.0.113.2:1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setChaintracksSSETestLimits(t, tc.client, tc.global)
			srv := testServer(t)
			addServerTestChain(t, srv, 1)

			first := startChaintracksTipStream(t, srv, tc.firstAddr)
			rejectedChaintracksTipStream(t, srv, tc.nextAddr)
			stopTestStream(t, first)
			admitted := startChaintracksTipStream(t, srv, tc.nextAddr)
			stopTestStream(t, admitted)
		})
	}
}
