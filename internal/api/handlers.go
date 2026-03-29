package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
)

// --- BEEF ---

// handleGetBEEF serves a stored transaction as a complete BEEF envelope.
func (s *Server) handleGetBEEF(w http.ResponseWriter, r *http.Request) {
	txid := r.PathValue("txid")
	if len(txid) != 64 {
		writeError(w, http.StatusBadRequest, "txid must be 64 hex characters")
		return
	}

	beefBytes, err := s.proofStore.GetBEEF(txid)
	if err != nil {
		writeError(w, http.StatusNotFound, "no BEEF envelope found for this txid")
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(beefBytes)
		return
	}

	confidence := ""
	if s.validator != nil {
		result, err := s.validator.ValidateBEEF(r.Context(), beefBytes)
		if err == nil {
			confidence = result.Confidence
		}
	}

	resp := map[string]interface{}{
		"txid": txid,
		"beef": hex.EncodeToString(beefBytes),
	}
	if confidence != "" {
		resp["confidence"] = confidence
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- Broadcast ---

// BroadcastResponse is the structured response from POST /broadcast.
type BroadcastResponse struct {
	TxID       string     `json:"txid"`
	Confidence string     `json:"confidence"`
	Stored     bool       `json:"stored"`
	Mempool    bool       `json:"mempool"`
	ARC        *ARCStatus `json:"arc,omitempty"`
	Message    string     `json:"message,omitempty"`
}

// ARCStatus is the structured ARC submission result.
type ARCStatus struct {
	Submitted bool   `json:"submitted"`
	TxStatus  string `json:"tx_status,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	beefBytes, err := readBEEF(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := s.validator.ValidateBEEF(context.Background(), beefBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("validation error: %v", err))
		return
	}

	if result.Confidence == spv.ConfidenceInvalid {
		writeJSON(w, http.StatusUnprocessableEntity, BroadcastResponse{
			TxID:       result.TxID,
			Confidence: result.Confidence,
			Message:    result.Message,
		})
		return
	}

	resp := BroadcastResponse{
		TxID:       result.TxID,
		Confidence: result.Confidence,
		Message:    result.Message,
	}

	if result.Confidence == spv.ConfidenceSPVVerified || result.Confidence == spv.ConfidencePartiallyVerified {
		if _, err := s.proofStore.StoreBEEF(beefBytes); err != nil {
			s.logger.Error("failed to store BEEF", "txid", result.TxID, "error", err)
		} else {
			resp.Stored = true
		}
	}

	if s.broadcaster != nil {
		if _, err := s.broadcaster.BroadcastBEEF(beefBytes); err != nil {
			s.logger.Error("mempool add failed", "txid", result.TxID, "error", err)
		} else {
			resp.Mempool = true
		}

		if r.URL.Query().Get("arc") == "true" {
			arcStatus := &ARCStatus{}
			if raw, ok := s.broadcaster.Mempool().Get(result.TxID); ok {
				arcResult, err := s.broadcaster.BroadcastToARC(raw)
				if err != nil {
					arcStatus.Error = err.Error()
				} else {
					arcStatus.Submitted = true
					arcStatus.TxStatus = arcResult.Status
				}
			} else {
				arcStatus.Error = "tx not in mempool"
			}
			resp.ARC = arcStatus
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// --- Data Envelope Endpoints ---

func (s *Server) handlePostData(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	env, err := envelope.UnmarshalEnvelope(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid envelope JSON: %v", err))
		return
	}

	if err := s.envelopeStore.Ingest(env); err != nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("rejected: %v", err))
		return
	}

	if s.gossipMgr != nil {
		s.gossipMgr.BroadcastEnvelope(env)
	}

	// Notify SSE subscribers (local POST)
	s.sseHub.notify(env)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"accepted": true,
		"topic":    env.Topic,
		"durable":  env.Durable,
		"key":      env.Key(),
	})
}

func (s *Server) handleQueryData(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}

	topic := r.URL.Query().Get("topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "topic query parameter required")
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
	}

	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		fmt.Sscanf(s, "%d", &since)
	}

	envs, err := s.envelopeStore.QueryByTopic(topic, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("query error: %v", err))
		return
	}

	// Filter by timestamp if since is set (results are newest-first)
	if since > 0 {
		filtered := envs[:0]
		for _, env := range envs {
			if env.Timestamp > since {
				filtered = append(filtered, env)
			}
		}
		envs = filtered
	}

	// Redact paid payloads for unauthenticated requests.
	// Authenticated = bearer token, successful x402 payment, or valid app token.
	// The x402/token middleware sets X-Anvil-Authed header before reaching this handler.
	isAuthed := r.Header.Get("X-Anvil-Authed") == "true" ||
		(s.authToken != "" && r.Header.Get("Authorization") == "Bearer "+s.authToken)

	// Clone envelopes for response — never mutate the in-memory store
	responseEnvs := make([]*envelope.Envelope, len(envs))
	for i, env := range envs {
		if !isAuthed && env.Monetization != nil && env.Monetization.PriceSats > 0 {
			// Shallow copy + redact payload
			redacted := *env
			redacted.Payload = "[paid content — access via HTTP 402]"
			responseEnvs[i] = &redacted
		} else {
			responseEnvs[i] = env
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"topic":     topic,
		"count":     len(responseEnvs),
		"envelopes": responseEnvs,
	})
}

func (s *Server) handleDeleteData(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}

	topic := r.URL.Query().Get("topic")
	key := r.URL.Query().Get("key")
	if topic == "" || key == "" {
		writeError(w, http.StatusBadRequest, "topic and key required (query params)")
		return
	}

	deleted, err := s.envelopeStore.Delete(topic, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("delete error: %v", err))
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "envelope not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted": true,
		"topic":   topic,
		"key":     key,
	})
}

// --- Overlay Endpoints ---

func (s *Server) handleOverlayLookup(w http.ResponseWriter, r *http.Request) {
	if s.overlayDir == nil {
		writeError(w, http.StatusServiceUnavailable, "overlay not configured")
		return
	}

	topic := r.URL.Query().Get("topic")
	if topic == "" {
		writeError(w, http.StatusBadRequest, "topic query parameter required")
		return
	}

	peers, err := s.overlayDir.LookupSHIPByTopic(topic)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("lookup error: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"topic": topic,
		"count": len(peers),
		"peers": peers,
	})
}

func (s *Server) handleOverlayRegister(w http.ResponseWriter, r *http.Request) {
	if s.overlayDir == nil {
		writeError(w, http.StatusServiceUnavailable, "overlay not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Script      string `json:"script"`
		TxID        string `json:"txid"`
		OutputIndex int    `json:"output_index"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	scriptBytes, err := hex.DecodeString(req.Script)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid script hex")
		return
	}

	disc := overlay.NewDiscoverer(s.overlayDir, s.logger)
	if err := disc.ProcessSHIPScript(scriptBytes, req.TxID, req.OutputIndex); err != nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("rejected: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"registered": true,
		"txid":       req.TxID,
	})
}

func (s *Server) handleOverlayDeregister(w http.ResponseWriter, r *http.Request) {
	if s.overlayDir == nil {
		writeError(w, http.StatusServiceUnavailable, "overlay not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Topic       string `json:"topic"`
		IdentityPub string `json:"identity_pub"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if req.Topic == "" || req.IdentityPub == "" {
		writeError(w, http.StatusBadRequest, "topic and identity_pub required")
		return
	}

	if err := s.overlayDir.RemoveSHIPPeer(req.Topic, req.IdentityPub); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("deregister error: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"deregistered": true,
		"topic":        req.Topic,
	})
}

// --- Request/Response helpers ---

func readBEEF(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read body")
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty request body")
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req struct {
			Beef string `json:"beef"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fmt.Errorf("invalid JSON")
		}
		beefBytes, err := hex.DecodeString(req.Beef)
		if err != nil {
			return nil, fmt.Errorf("invalid hex in beef field")
		}
		return beefBytes, nil
	}

	return body, nil
}

// handleAppRedirect serves /app/{name} — redirects to the latest inscription
// for a named app from the anvil:catalog topic. Every node in the mesh can
// serve this because the catalog gossips across all peers.
func (s *Server) handleAppRedirect(w http.ResponseWriter, r *http.Request) {
	appName := r.PathValue("name")
	if appName == "" {
		writeError(w, http.StatusBadRequest, "app name required")
		return
	}

	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "no envelope store")
		return
	}

	envs, err := s.envelopeStore.QueryByTopic("anvil:catalog", 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "catalog query failed")
		return
	}

	// Search for matching app
	for _, env := range envs {
		var listing struct {
			Name          string `json:"name"`
			ContentOrigin string `json:"content_origin"`
		}
		if err := json.Unmarshal([]byte(env.Payload), &listing); err != nil {
			continue
		}
		if strings.EqualFold(listing.Name, appName) && listing.ContentOrigin != "" {
			target := "/content/" + listing.ContentOrigin
			if s.publicURL != "" {
				target = s.publicURL + target
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
	}

	writeError(w, http.StatusNotFound, fmt.Sprintf("app %q not found in catalog or has no content_origin", appName))
}

// handleAppRedirectWithFallback is like handleAppRedirect but falls back
// to a configured content origin when the catalog has no matching entry.
// Used by /explorer to survive catalog expiry.
func (s *Server) handleAppRedirectWithFallback(w http.ResponseWriter, r *http.Request, fallbackOrigin string) {
	appName := r.PathValue("name")

	if s.envelopeStore != nil {
		envs, err := s.envelopeStore.QueryByTopic("anvil:catalog", 100)
		if err == nil {
			for _, env := range envs {
				var listing struct {
					Name          string `json:"name"`
					ContentOrigin string `json:"content_origin"`
				}
				if err := json.Unmarshal([]byte(env.Payload), &listing); err != nil {
					continue
				}
				if strings.EqualFold(listing.Name, appName) && listing.ContentOrigin != "" {
					target := "/content/" + listing.ContentOrigin
					if s.publicURL != "" {
						target = s.publicURL + target
					}
					http.Redirect(w, r, target, http.StatusFound)
					return
				}
			}
		}
	}

	// Fall back to configured origin
	if fallbackOrigin != "" {
		target := "/content/" + fallbackOrigin
		if s.publicURL != "" {
			target = s.publicURL + target
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	writeError(w, http.StatusNotFound, "explorer not configured")
}
