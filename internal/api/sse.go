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
	seqID atomic.Int64                                     // monotonic event ID
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Check auth status for payload redaction (same logic as GET /data)
	isAuthed := r.Header.Get("X-Anvil-Authed") == "true" ||
		(s.authToken != "" && r.Header.Get("Authorization") == "Bearer "+s.authToken)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	// If reconnecting with Last-Event-ID, warn about potential gap
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		fmt.Fprintf(w, ": reconnected after id %s — events between disconnect and reconnect may be lost; use GET /data?since=TIMESTAMP to backfill\n\n", lastID)
		flusher.Flush()
	}

	flusher.Flush()

	// Track demand for this topic.
	if s.gossipMgr != nil {
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
			// Redact paid payloads for unauthenticated subscribers
			outEnv := env
			if !isAuthed && env.Monetization != nil && env.Monetization.PriceSats > 0 {
				redacted := *env
				redacted.Payload = "[paid content — access via HTTP 402]"
				outEnv = &redacted
			}

			data, err := json.Marshal(outEnv)
			if err != nil {
				continue
			}
			id := s.sseHub.nextID()
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", id, data)
			flusher.Flush()
		}
	}
}
