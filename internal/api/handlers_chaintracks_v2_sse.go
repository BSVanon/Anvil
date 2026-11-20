package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
)

// --- Chaintracks v2 SSE: tip/stream and reorg/stream ---
//
// Canonical event framing: routes/fiber/routes.go:343-396 handleTipStream
// (sends the current tip immediately, then "data: <json>\n\n" per new tip)
// and :398-445 handleReorgStream (no initial event, "data: <json>\n\n" per
// reorg); both send a periodic comment-line to keep an idle connection alive
// through a proxy. The canonical Go client's own parser (client.go:258-311
// readSSE/readReorgSSE) only looks for a "data: " line prefix and silently
// skips everything else — so the keepalive's own wording doesn't need to
// match canonical's "keepalive" literally. This reuses Anvil's own existing
// messagebox-SSE heartbeat convention instead (sse_messages.go's
// sseHeartbeatInterval and ": ping\n\n" line), per the spec's instruction to
// reuse Anvil's existing SSE helpers for the parts canonical doesn't dictate
// the wire format of.
//
// Fed from internal/headers.Store's SubscribeTip/SubscribeReorg (feed.go):
// AddHeaders publishes a new tip on every forward append; ReorgTo publishes
// both a ReorgNotice and a new tip on every adopted reorg (a forward append
// can never fork below the tip, so ReorgTo is the only source of a genuine
// reorg event). Both publishes are non-blocking sends on a 1-buffered
// channel — a stream reader that falls behind simply misses an
// intermediate tip/reorg rather than ever stalling header sync.
//
// These are no-login public routes (openPublic: no payment/token gate), so
// they are bounded the same way messagebox SSE already is: a per-client-IP
// cap and a node-wide cap, released on disconnect. There is no per-identity
// axis here (no login), unlike messagebox SSE's per-identity cap.

// chaintracksSSEMaxPerClient / chaintracksSSEMaxGlobal bound concurrent
// tip/stream + reorg/stream connections. Vars, not consts, so tests can
// shrink them (mirrors sse_caps_test.go's own pattern for messagebox SSE).
//
// Rationale for the numbers: each live stream pins one handler goroutine
// (minimum ~2-8KB stack) plus one small fixed-capacity buffered channel —
// tip/stream's is a chan uint32 (cap 1); reorg/stream's is a chan
// headers.ReorgNotice (cap 1), whose one in-flight value carries at most
// maxReorgDepth=144 orphaned hashes (~4.6KB, internal/headers/store.go).
// Call it on the order of 10KB of Go-side memory per connection, excluding
// kernel socket buffers — at the global cap of 2000 that is tens of MB,
// a deliberately modest ceiling for a BSV node.
//
// Lower than the messagebox SSE caps (sse_messages.go:
// sseMaxStreamsPerClientKey=64, sseMaxStreamsNodeWide=10000): these are
// no-login public infrastructure routes expected to serve a modest number
// of long-lived header-sync clients per node, not messagebox's
// per-identity authenticated inboxes serving a potentially large end-user
// base. Both pairs of caps bound the same hazard — unbounded goroutine/
// memory growth from concurrent streams — just calibrated to a different
// expected client population.
var (
	chaintracksSSEMaxPerClient = 16
	chaintracksSSEMaxGlobal    = 2000
	liveChaintracksStreams     = struct {
		sync.Mutex
		byClient map[string]int
		total    int
	}{byClient: make(map[string]int)}
)

// acquireChaintracksStream reserves one concurrent-stream slot for
// clientKey, or refuses if either cap is already at its limit. The returned
// release function must be called (typically via defer) when the stream
// ends.
func acquireChaintracksStream(clientKey string) (release func(), ok bool) {
	liveChaintracksStreams.Lock()
	defer liveChaintracksStreams.Unlock()
	if liveChaintracksStreams.byClient[clientKey] >= chaintracksSSEMaxPerClient ||
		liveChaintracksStreams.total >= chaintracksSSEMaxGlobal {
		return nil, false
	}
	liveChaintracksStreams.byClient[clientKey]++
	liveChaintracksStreams.total++
	return func() {
		liveChaintracksStreams.Lock()
		defer liveChaintracksStreams.Unlock()
		liveChaintracksStreams.byClient[clientKey]--
		if liveChaintracksStreams.byClient[clientKey] == 0 {
			delete(liveChaintracksStreams.byClient, clientKey)
		}
		liveChaintracksStreams.total--
	}, true
}

// chaintracksStreamClientKey mirrors messageStreamClientKey (sse_messages.go
// :62-68), keyed off the limiter actually applied to these openPublic
// routes (s.rateLimiter) rather than the messagebox limiter.
func (s *Server) chaintracksStreamClientKey(r *http.Request) string {
	trustProxy, trustHops := false, 1
	if s.rateLimiter != nil {
		trustProxy, trustHops = s.rateLimiter.trustProxy, s.rateLimiter.trustHops
	}
	return rateLimitKey(clientIP(r, trustProxy, trustHops))
}

// writeChaintracksStreamLimit refuses a stream connection over the
// per-client or node-wide cap, in the same bare {"error":"..."} shape every
// other chaintracks v2 error uses.
func writeChaintracksStreamLimit(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusTooManyRequests, "too many concurrent streams")
}

// handleChaintracksV2TipStream serves GET /chaintracks/v2/tip/stream.
// Canonical: routes/fiber/routes.go:343-396 handleTipStream.
func (s *Server) handleChaintracksV2TipStream(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	release, ok := acquireChaintracksStream(s.chaintracksStreamClientKey(r))
	if !ok {
		writeChaintracksStreamLimit(w)
		return
	}
	defer release()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Canonical sends the current tip immediately on connect.
	if err := s.writeChaintracksV2TipEvent(w, s.headerStore.Tip()); err != nil {
		return
	}

	ch := make(chan uint32, 1)
	unsub := s.headerStore.SubscribeTip(ch)
	defer unsub()

	ping := time.NewTicker(sseHeartbeatInterval)
	defer ping.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if err := writeSSE(w, ": ping\n\n"); err != nil {
				return
			}
		case height := <-ch:
			if err := s.writeChaintracksV2TipEvent(w, height); err != nil {
				return
			}
		}
	}
}

// writeChaintracksV2TipEvent writes one SSE data frame carrying the bare
// header JSON for height, under sse_deadline.go's per-write deadline. A
// transient read/decode failure is skipped rather than sent malformed — the
// stream just waits for the next tip; that is not a write error and never
// aborts the connection. A genuine write/flush error (including a stalled
// client exceeding the deadline) IS returned, so the caller's loop returns
// and its deferred release() frees the stream slot.
func (s *Server) writeChaintracksV2TipEvent(w http.ResponseWriter, height uint32) error {
	raw, err := s.headerStore.HeaderAtHeight(height)
	if err != nil {
		return nil
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		return nil
	}
	data, err := json.Marshal(chaintracksV2HeaderFor(hdr, height))
	if err != nil {
		return nil
	}
	return writeSSE(w, fmt.Sprintf("data: %s\n\n", data))
}

// handleChaintracksV2ReorgStream serves GET /chaintracks/v2/reorg/stream.
// Canonical: routes/fiber/routes.go:398-445 handleReorgStream — no initial
// event (only tip/stream sends one on connect).
func (s *Server) handleChaintracksV2ReorgStream(w http.ResponseWriter, r *http.Request) {
	if _, ok := w.(http.Flusher); !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	release, ok := acquireChaintracksStream(s.chaintracksStreamClientKey(r))
	if !ok {
		writeChaintracksStreamLimit(w)
		return
	}
	defer release()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := writeSSE(w, ""); err != nil {
		return
	}

	ch := make(chan headers.ReorgNotice, 1)
	unsub := s.headerStore.SubscribeReorg(ch)
	defer unsub()

	ping := time.NewTicker(sseHeartbeatInterval)
	defer ping.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if err := writeSSE(w, ": ping\n\n"); err != nil {
				return
			}
		case notice := <-ch:
			if err := s.writeChaintracksV2ReorgEvent(w, notice); err != nil {
				return
			}
		}
	}
}

// writeChaintracksV2ReorgEvent writes one SSE data frame in the canonical
// ReorgEvent shape (chaintracks/types.go:41-57): orphanedHashes,
// commonAncestor, newTip, depth. commonAncestor and newTip are looked up
// fresh from the store — both heights are still present after a reorg (only
// the orphaned range was deleted), which is why ReorgNotice carries the
// orphaned hashes directly instead of heights to look up. Sits under
// sse_deadline.go's per-write deadline, with the same skip-vs-error split as
// writeChaintracksV2TipEvent: a JSON marshal failure is skipped (never
// happens for this map in practice), while a genuine write/flush error is
// returned so the caller's loop can return and release its stream slot.
func (s *Server) writeChaintracksV2ReorgEvent(w http.ResponseWriter, notice headers.ReorgNotice) error {
	event := map[string]any{
		"orphanedHashes": chaintracksV2HashStrings(notice.OrphanedHashes),
		"depth":          uint32(len(notice.OrphanedHashes)), //nolint:gosec // bounded by maxReorgDepth
	}
	if raw, err := s.headerStore.HeaderAtHeight(notice.ForkHeight); err == nil {
		if hdr, err := decodeWireHeaderV2(raw); err == nil {
			event["commonAncestor"] = chaintracksV2HeaderFor(hdr, notice.ForkHeight)
		}
	}
	if raw, err := s.headerStore.HeaderAtHeight(notice.NewTip); err == nil {
		if hdr, err := decodeWireHeaderV2(raw); err == nil {
			event["newTip"] = chaintracksV2HeaderFor(hdr, notice.NewTip)
		}
	}
	data, err := json.Marshal(event)
	if err != nil {
		return nil
	}
	return writeSSE(w, fmt.Sprintf("data: %s\n\n", data))
}

func chaintracksV2HashStrings(hashes []chainhash.Hash) []string {
	out := make([]string, len(hashes))
	for i, h := range hashes {
		out[i] = h.String()
	}
	return out
}
