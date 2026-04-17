package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// messageHub fans out new messages to SSE subscribers by recipient+messageBox.
type messageHub struct {
	mu    sync.RWMutex
	subs  map[string]map[chan *messaging.Message]struct{} // "recipient:messageBox" → set of channels
	seqID atomic.Int64
}

func newMessageHub() *messageHub {
	return &messageHub{
		subs: make(map[string]map[chan *messaging.Message]struct{}),
	}
}

func messageSubKey(recipient, messageBox string) string {
	return recipient + ":" + messageBox
}

// subscribe registers a channel for a recipient+messageBox pair.
// Returns an unsubscribe function.
func (h *messageHub) subscribe(recipient, messageBox string, ch chan *messaging.Message) func() {
	key := messageSubKey(recipient, messageBox)
	h.mu.Lock()
	if h.subs[key] == nil {
		h.subs[key] = make(map[chan *messaging.Message]struct{})
	}
	h.subs[key][ch] = struct{}{}
	h.mu.Unlock()

	return func() {
		h.mu.Lock()
		delete(h.subs[key], ch)
		if len(h.subs[key]) == 0 {
			delete(h.subs, key)
		}
		h.mu.Unlock()
	}
}

// notify sends a message to all subscribers matching recipient+messageBox.
// Non-blocking: slow clients are skipped.
func (h *messageHub) notify(msg *messaging.Message) {
	key := messageSubKey(msg.Recipient, msg.MessageBox)
	h.mu.RLock()
	defer h.mu.RUnlock()

	for ch := range h.subs[key] {
		select {
		case ch <- msg:
		default:
			// slow client — drop rather than block
		}
	}
}

// nextID returns a monotonically increasing event ID for SSE streams.
func (h *messageHub) nextID() int64 {
	return h.seqID.Add(1)
}

// handleMessageSubscribe is the SSE endpoint: GET /messages/subscribe?recipient=X&messageBox=Y
// Requires auth. Pushes new messages as they arrive in real time.
func (s *Server) handleMessageSubscribe(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	recipient := r.URL.Query().Get("recipient")
	messageBox := r.URL.Query().Get("messageBox")
	if messageBox == "" {
		writeError(w, http.StatusBadRequest, "messageBox query parameter required")
		return
	}
	// Default recipient to node identity if not provided.
	if recipient == "" {
		recipient = s.identityPub
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	// If reconnecting with Last-Event-ID, warn about potential gap.
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		fmt.Fprintf(w, ": reconnected after id %s — use POST /listMessages to backfill\n\n", lastID)
		flusher.Flush()
	}

	flusher.Flush()

	ch := make(chan *messaging.Message, 16)
	unsub := s.msgHub.subscribe(recipient, messageBox, ch)
	defer unsub()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			id := s.msgHub.nextID()
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", id, data)
			flusher.Flush()
		}
	}
}
