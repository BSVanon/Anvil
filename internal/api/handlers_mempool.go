package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/BSVanon/Anvil/internal/mempool"
)

// handleAddWatch handles POST /mempool/watch — add addresses to watch list.
// Body: {"addresses": ["1abc...", "1def..."]}
func (s *Server) handleAddWatch(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "mempool watcher not enabled")
		return
	}

	var req struct {
		Addresses []string `json:"addresses"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Addresses) == 0 {
		writeError(w, http.StatusBadRequest, "addresses array required")
		return
	}

	var added, failed int
	var errors []string
	for _, addr := range req.Addresses {
		if err := s.watcher.Add(addr); err != nil {
			failed++
			errors = append(errors, err.Error())
		} else {
			added++
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"added":    added,
		"failed":   failed,
		"errors":   errors,
		"watching": s.watcher.Count(),
	})
}

// handleRemoveWatch handles DELETE /mempool/watch — remove addresses.
// Body: {"addresses": ["1abc..."]}
func (s *Server) handleRemoveWatch(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "mempool watcher not enabled")
		return
	}

	var req struct {
		Addresses []string `json:"addresses"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	for _, addr := range req.Addresses {
		s.watcher.Remove(addr)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"removed":  len(req.Addresses),
		"watching": s.watcher.Count(),
	})
}

// handleListWatch handles GET /mempool/watch — list watched addresses + stats.
func (s *Server) handleListWatch(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "mempool watcher not enabled")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"addresses": s.watcher.List(),
		"count":     s.watcher.Count(),
		"hits":      s.watcher.Hits(),
		"spends":    s.watcher.Spends(),
	})
}

// handleWatchHistory handles GET /mempool/watch/history?address=X&limit=N
func (s *Server) handleWatchHistory(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "mempool watcher not enabled")
		return
	}

	address := r.URL.Query().Get("address")
	if address == "" {
		writeError(w, http.StatusBadRequest, "address query parameter required")
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		_, _ = fmt.Sscanf(l, "%d", &limit) // bad input keeps default
		if limit <= 0 || limit > 500 {
			limit = 50
		}
	}

	hits := s.watcher.History(address, limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"address": address,
		"hits":    hits,
		"count":   len(hits),
	})
}

// handleWatchSubscribe handles GET /mempool/watch/subscribe?address=X — SSE stream.
// Pass address="" or omit to receive all watch hits.
func (s *Server) handleWatchSubscribe(w http.ResponseWriter, r *http.Request) {
	if s.watcher == nil {
		writeError(w, http.StatusServiceUnavailable, "mempool watcher not enabled")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	address := r.URL.Query().Get("address")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := make(chan mempool.WatchHit, 16)
	unsub := s.watcher.Subscribe(address, ch)
	defer unsub()

	ctx := r.Context()
	var seq int64
	for {
		select {
		case <-ctx.Done():
			return
		case hit := <-ch:
			data, err := json.Marshal(hit)
			if err != nil {
				continue
			}
			seq++
			fmt.Fprintf(w, "id: %d\ndata: %s\n\n", seq, data)
			flusher.Flush()
		}
	}
}
