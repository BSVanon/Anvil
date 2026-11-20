package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/overlay"
)

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

	// Catalog dedup: one entry per publisher per topic. Latest wins.
	if env.Topic == "anvil:catalog" && env.Durable {
		if n := s.envelopeStore.DeduplicateDurable(env); n > 0 {
			s.logger.Info("catalog dedup: removed older entries", "pubkey", env.Pubkey[:16], "removed", n)
		}
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

// handleNodePublish signs an envelope with the node's identity key and publishes it.
// Operator-only (requireAuth). Allows the operator to publish metadata, identity,
// and catalog envelopes without needing external signing tools.
func (s *Server) handleNodePublish(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}
	if s.signingKey == nil {
		writeError(w, http.StatusServiceUnavailable, "no signing key configured")
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

	// Set timestamp if missing
	if env.Timestamp == 0 {
		env.Timestamp = time.Now().Unix()
	}

	// Sign with node identity key
	env.Sign(s.signingKey)

	if err := s.envelopeStore.Ingest(env); err != nil {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("rejected: %v", err))
		return
	}

	// Catalog dedup
	if env.Topic == "anvil:catalog" && env.Durable {
		if n := s.envelopeStore.DeduplicateDurable(env); n > 0 {
			s.logger.Info("catalog dedup: removed older entries", "pubkey", env.Pubkey[:16], "removed", n)
		}
	}

	if s.gossipMgr != nil {
		s.gossipMgr.BroadcastEnvelope(env)
	}

	s.sseHub.notify(env)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"accepted":  true,
		"topic":     env.Topic,
		"durable":   env.Durable,
		"key":       env.Key(),
		"signed_by": env.Pubkey,
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

	// authed gates `private` envelope omission below: operator bearer token
	// ONLY — a verified x402 payment or a valid app token is never
	// sufficient (docs/ANVIL_PRIVATE_FLAG_CONTRACT.md). authedOrPaid
	// additionally accepts a verified payment and gates paid/monetized
	// payload redaction, unchanged from before the split.
	authed := s.isAuthed(r)
	authedOrPaid := s.isAuthedOrPaid(r)

	// Track demand for this topic — operator reads never count, so the
	// operator's own reads can't be mistaken for mesh-wide demand.
	if s.gossipMgr != nil && !authed {
		s.gossipMgr.IncrDemand(topic)
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		_, _ = fmt.Sscanf(l, "%d", &limit) // bad input keeps default
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
	}

	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		_, _ = fmt.Sscanf(s, "%d", &since) // bad input keeps zero
	}

	// Fetch unlimited and filter private envelopes out first, before since
	// or limit ever run — the same order internal/gossip/handlers.go uses
	// for a peer pull (dropPrivate then visiblePage). Filtering after a
	// limit, or after a since cutoff, truncates the candidate set on
	// unfiltered data first: a caller can then binary-search a private
	// envelope's write time by varying limit/since and watching the
	// returned count shift. Fetching unlimited and dropping private
	// envelopes immediately removes that signal; limit and since then
	// apply only to what the caller may actually see.
	envs, err := s.envelopeStore.QueryByTopic(topic, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("query error: %v", err))
		return
	}
	if !authed {
		envs = dropPrivateEnvelopes(envs)
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

	if limit > 0 && len(envs) > limit {
		envs = envs[:limit]
	}

	// Clone envelopes for response — never mutate the in-memory store.
	// Private envelopes were already dropped above for callers who are not
	// authenticated, omitted entirely (not just payload-redacted) so
	// neither the sealed blob nor its metadata (topic/pubkey/timestamp/size)
	// leaks; operator bearer token callers see them in full. Paying never
	// unlocks one.
	responseEnvs := make([]*envelope.Envelope, 0, len(envs))
	for _, env := range envs {
		// A validated app token (Model 4) additionally unredacts an envelope
		// on EXACTLY the topic it was validated for — never a private
		// envelope (dropped above regardless of this check).
		if !authedOrPaid && !appTokenTopicMatches(r, env.Topic) && env.Monetization != nil && env.Monetization.PriceSats > 0 {
			// Shallow copy + redact payload
			redacted := *env
			redacted.Payload = "[paid content — access via HTTP 402]"
			responseEnvs = append(responseEnvs, &redacted)
		} else {
			responseEnvs = append(responseEnvs, env)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"topic":     topic,
		"count":     len(responseEnvs),
		"envelopes": responseEnvs,
	})
}

// dropPrivateEnvelopes returns envs with every Private envelope removed,
// reusing the backing array (same in-place-filter shape as
// internal/gossip/handlers.go's dropPrivate). Callers that need operator
// visibility must not call this at all, not call it and then add private
// envelopes back — this function has no "except operator" mode on purpose,
// so every call site is unambiguous about which caller it is filtering for.
func dropPrivateEnvelopes(envs []*envelope.Envelope) []*envelope.Envelope {
	kept := envs[:0]
	for _, env := range envs {
		if !env.Private {
			kept = append(kept, env)
		}
	}
	return kept
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
