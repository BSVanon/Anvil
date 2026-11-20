package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// envelopeHub fans out new envelopes to SSE subscribers by topic.
type envelopeHub struct {
	mu    sync.RWMutex
	subs  map[string]map[chan *envelope.Envelope]struct{} // topic → set of channels
	seqID atomic.Int64                                    // monotonic event ID
}

func newEnvelopeHub() *envelopeHub {
	return &envelopeHub{
		subs: make(map[string]map[chan *envelope.Envelope]struct{}),
	}
}

// subscribe registers a channel for a topic. Returns an unsubscribe function.
func (h *envelopeHub) subscribe(topic string, ch chan *envelope.Envelope) func() {
	h.mu.Lock()
	if h.subs[topic] == nil {
		h.subs[topic] = make(map[chan *envelope.Envelope]struct{})
	}
	h.subs[topic][ch] = struct{}{}
	h.mu.Unlock()

	return func() {
		h.mu.Lock()
		delete(h.subs[topic], ch)
		if len(h.subs[topic]) == 0 {
			delete(h.subs, topic)
		}
		h.mu.Unlock()
	}
}

// notify sends an envelope to all subscribers of its topic.
// Non-blocking: slow clients are skipped (their channel is full).
func (h *envelopeHub) notify(env *envelope.Envelope) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for ch := range h.subs[env.Topic] {
		select {
		case ch <- env:
		default:
			// slow client — drop rather than block the fan-out path
		}
	}
}

// nextID returns a monotonically increasing event ID for SSE streams.
func (h *envelopeHub) nextID() int64 {
	return h.seqID.Add(1)
}

// handleSubscribe is the SSE endpoint: GET /data/subscribe?topic=X
// Routed through openRead so rate limiting, payment gates, and token gates apply.
// Paid payloads are redacted for unauthenticated clients, matching GET /data behavior.
// Events carry monotonic IDs; on reconnect with Last-Event-ID, a gap warning is sent.
func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	topic := r.URL.Query().Get("topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "topic query parameter required")
		return
	}

	if _, ok := w.(http.Flusher); !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// authed gates private-envelope omission; a payment or an app token
	// unredacts only the monetized envelopes it covers, each by its own rule
	// (envelopeForRequest, envelope_redaction.go), the same as GET /data
	// (handlers.go). Paying never unlocks a private envelope over SSE either.
	authed := s.isAuthed(r)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	// If reconnecting with Last-Event-ID, warn about potential gap. Always
	// flush at least once (reconnectMsg == "" when there's nothing to warn
	// about) under a fresh write deadline (sse_deadline.go) — a stalled
	// client that never reads must not block here forever.
	reconnectMsg := ""
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		reconnectMsg = fmt.Sprintf(": reconnected after id %s — events between disconnect and reconnect may be lost; use GET /data?since=TIMESTAMP to backfill\n\n", lastID)
	}
	if err := writeSSE(w, reconnectMsg); err != nil {
		return
	}

	// Track demand for this topic — operator reads never count, so the
	// operator's own subscriptions can't be mistaken for mesh-wide demand.
	if s.gossipMgr != nil && !authed {
		s.gossipMgr.IncrDemand(topic)
	}

	ch := make(chan *envelope.Envelope, 16)
	unsub := s.sseHub.subscribe(topic, ch)
	defer unsub()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case env := <-ch:
			// Private envelopes are never streamed to callers who are not
			// authenticated (read-gated, matching GET /data omission). A
			// verified payment alone is never sufficient.
			if env.Private && !authed {
				continue
			}
			// The hub delivers only envelopes on exactly the subscribed topic
			// (envelopeHub.notify), so every envelope here is on the topic
			// this request's payment or token was checked against. Each is
			// still served or redacted by its own monetization.
			outEnv := envelopeForRequest(r, env, authed)

			data, err := json.Marshal(outEnv)
			if err != nil {
				continue
			}
			id := s.sseHub.nextID()
			if err := writeSSE(w, fmt.Sprintf("id: %d\ndata: %s\n\n", id, data)); err != nil {
				return
			}
		}
	}
}
