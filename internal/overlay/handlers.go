package overlay

import (
	"encoding/json"
	"io"
	"net/http"
)

// RegisterHTTPHandlers adds BRC-22/24 overlay endpoints to a mux.
//
// POST /overlay/submit — BRC-22 transaction submission (TaggedBEEF)
// POST /overlay/query — BRC-24 query resolution
// GET  /overlay/topics — list registered topic managers
// GET  /overlay/services — list registered lookup services
func (e *Engine) RegisterHTTPHandlers(mux *http.ServeMux, corsWrap func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("POST /overlay/submit", corsWrap(e.handleSubmit))
	mux.HandleFunc("POST /overlay/query", corsWrap(e.handleLookup))
	mux.HandleFunc("GET /overlay/topics", corsWrap(e.handleListTopics))
	mux.HandleFunc("GET /overlay/services", corsWrap(e.handleListServices))
}

// handleSubmit processes a BRC-22 transaction submission.
//
// Accepts two formats:
// 1. JSON body: { "beef": [bytes], "topics": ["tm_ship", "tm_uhrp"] }
// 2. Binary body (application/octet-stream) with X-Topics header
//
// Returns STEAK: { "tm_ship": { "outputsToAdmit": [0], ... } }
func (e *Engine) handleSubmit(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")

	var txData []byte
	var topics []string

	if contentType == "application/octet-stream" {
		// Babbage-compatible binary format
		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB max
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
			return
		}
		txData = body

		topicsHeader := r.Header.Get("X-Topics")
		if topicsHeader != "" {
			if err := json.Unmarshal([]byte(topicsHeader), &topics); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid X-Topics header"})
				return
			}
		}
	} else {
		// JSON format
		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
			return
		}
		var tagged TaggedBEEF
		if err := json.Unmarshal(body, &tagged); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		txData = tagged.BEEF
		topics = tagged.Topics
	}

	if len(txData) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty transaction data"})
		return
	}
	if len(topics) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no topics specified"})
		return
	}

	steak, err := e.Submit(txData, topics)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, steak)
}

// handleLookup processes a BRC-24 query.
//
// POST body: { "service": "ls_uhrp", "query": { "content_hash": "abc..." } }
// Returns: { "type": "output-list", "outputs": [...] }
func (e *Engine) handleLookup(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	var question LookupQuestion
	if err := json.Unmarshal(body, &question); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid query: " + err.Error()})
		return
	}

	answer, err := e.Lookup(question)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, answer)
}

// handleListTopics returns all registered topic managers.
func (e *Engine) handleListTopics(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string]interface{})
	for name, tm := range e.topics {
		result[name] = map[string]interface{}{
			"documentation": tm.GetDocumentation(),
			"metadata":      tm.GetMetadata(),
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// handleListServices returns all registered lookup services.
func (e *Engine) handleListServices(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string]interface{})
	for name, ls := range e.lookups {
		result[name] = map[string]interface{}{
			"documentation": ls.GetDocumentation(),
			"metadata":      ls.GetMetadata(),
			"topics":        e.lookupTopics[name],
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
