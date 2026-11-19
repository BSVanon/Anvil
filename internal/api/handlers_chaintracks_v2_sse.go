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
	flusher, ok := w.(http.Flusher)
	if !ok {
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
	s.writeChaintracksV2TipEvent(w, s.headerStore.Tip())
	flusher.Flush()

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
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case height := <-ch:
			s.writeChaintracksV2TipEvent(w, height)
			flusher.Flush()
		}
	}
}

// writeChaintracksV2TipEvent writes one SSE data frame carrying the bare
// header JSON for height. A transient read/decode failure is skipped rather
// than sent malformed — the stream just waits for the next tip.
func (s *Server) writeChaintracksV2TipEvent(w http.ResponseWriter, height uint32) {
	raw, err := s.headerStore.HeaderAtHeight(height)
	if err != nil {
		return
	}
	hdr, err := decodeWireHeaderV2(raw)
	if err != nil {
		return
	}
	data, err := json.Marshal(chaintracksV2HeaderFor(hdr, height))
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

// handleChaintracksV2ReorgStream serves GET /chaintracks/v2/reorg/stream.
// Canonical: routes/fiber/routes.go:398-445 handleReorgStream — no initial
// event (only tip/stream sends one on connect).
func (s *Server) handleChaintracksV2ReorgStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
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
	flusher.Flush()

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
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case notice := <-ch:
			s.writeChaintracksV2ReorgEvent(w, notice)
			flusher.Flush()
		}
	}
}

// writeChaintracksV2ReorgEvent writes one SSE data frame in the canonical
// ReorgEvent shape (chaintracks/types.go:41-57): orphanedHashes,
// commonAncestor, newTip, depth. commonAncestor and newTip are looked up
// fresh from the store — both heights are still present after a reorg (only
// the orphaned range was deleted), which is why ReorgNotice carries the
// orphaned hashes directly instead of heights to look up.
func (s *Server) writeChaintracksV2ReorgEvent(w http.ResponseWriter, notice headers.ReorgNotice) {
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
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func chaintracksV2HashStrings(hashes []chainhash.Hash) []string {
	out := make([]string, len(hashes))
	for i, h := range hashes {
		out[i] = h.String()
	}
	return out
}
