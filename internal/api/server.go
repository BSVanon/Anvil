package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
)

// Server is the Anvil REST API server.
type Server struct {
	headerStore   *headers.Store
	proofStore    *spv.ProofStore
	envelopeStore *envelope.Store
	overlayDir    *overlay.Directory
	validator     *spv.Validator
	broadcaster   *txrelay.Broadcaster
	logger        *slog.Logger
	mux           *http.ServeMux
	authToken     string
}

// NewServer creates a new REST API server.
func NewServer(
	headerStore *headers.Store,
	proofStore *spv.ProofStore,
	envelopeStore *envelope.Store,
	overlayDir *overlay.Directory,
	validator *spv.Validator,
	broadcaster *txrelay.Broadcaster,
	authToken string,
	logger *slog.Logger,
) *Server {
	s := &Server{
		headerStore:   headerStore,
		proofStore:    proofStore,
		envelopeStore: envelopeStore,
		overlayDir:    overlayDir,
		validator:     validator,
		broadcaster:   broadcaster,
		logger:        logger,
		mux:           http.NewServeMux(),
		authToken:     authToken,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Open read endpoints
	s.mux.HandleFunc("GET /status", s.handleStatus)
	s.mux.HandleFunc("GET /headers/tip", s.handleHeadersTip)
	s.mux.HandleFunc("GET /tx/{txid}/beef", s.handleGetBEEF)
	s.mux.HandleFunc("GET /data", s.handleQueryData)
	s.mux.HandleFunc("GET /overlay/lookup", s.handleOverlayLookup)

	// Authenticated write endpoints
	s.mux.HandleFunc("POST /broadcast", s.requireAuth(s.handleBroadcast))
	s.mux.HandleFunc("POST /data", s.requireAuth(s.handlePostData))
	s.mux.HandleFunc("POST /overlay/register", s.requireAuth(s.handleOverlayRegister))
	s.mux.HandleFunc("POST /overlay/deregister", s.requireAuth(s.handleOverlayDeregister))
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// Mux returns the underlying ServeMux for external route registration.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// RequireAuth is the exported auth middleware for external route registration.
func (s *Server) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(next)
}

// --- Handlers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	tip := s.headerStore.Tip()
	work := s.headerStore.Work()
	resp := map[string]interface{}{
		"node":    "anvil",
		"version": "0.1.0",
		"headers": map[string]interface{}{
			"height": tip,
			"work":   work.String(),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHeadersTip(w http.ResponseWriter, r *http.Request) {
	tip := s.headerStore.Tip()
	hash, err := s.headerStore.HashAtHeight(tip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get tip hash")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"height": tip,
		"hash":   hash.String(),
	})
}

// handleGetBEEF serves a stored transaction as a complete BEEF envelope.
// GET /tx/:txid/beef
//
// Returns the full BEEF binary (hex-encoded in JSON, or raw binary if
// Accept: application/octet-stream). This includes the transaction, its
// full input ancestry, and all BRC-74 merkle proofs — everything needed
// for the consumer to independently verify the transaction.
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

	// If client wants raw binary, serve it directly
	if strings.Contains(r.Header.Get("Accept"), "application/octet-stream") {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(beefBytes)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"txid": txid,
		"beef": hex.EncodeToString(beefBytes),
	})
}

// BroadcastResponse is the structured response from POST /broadcast.
// All fields are machine-readable — clients should not parse Message strings.
type BroadcastResponse struct {
	TxID       string             `json:"txid"`
	Confidence string             `json:"confidence"`
	Stored     bool               `json:"stored"`
	Mempool    bool               `json:"mempool"`
	ARC        *ARCStatus         `json:"arc,omitempty"`
	Message    string             `json:"message,omitempty"`
}

// ARCStatus is the structured ARC submission result.
type ARCStatus struct {
	Submitted bool   `json:"submitted"`
	TxStatus  string `json:"tx_status,omitempty"` // SEEN_ON_NETWORK, MINED, etc.
	Error     string `json:"error,omitempty"`
}

// handleBroadcast is the core BEEF acceptance endpoint.
// POST /broadcast
// POST /broadcast?arc=true
//
// Per the architecture contract:
// 1. Parse and validate BEEF against local header chain
// 2. Return a structured confidence level
// 3. Store the proven envelope for future serving via GET /tx/:txid/beef
// 4. Add raw tx to local mempool
// 5. Optionally submit to ARC via ?arc=true
//
// P2P peer relay is not yet implemented — mempool is local only.
func (s *Server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	beefBytes, err := readBEEF(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate BEEF against local headers
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

	// Store full BEEF if at least partially verified
	if result.Confidence == spv.ConfidenceSPVVerified || result.Confidence == spv.ConfidencePartiallyVerified {
		if _, err := s.proofStore.StoreBEEF(beefBytes); err != nil {
			s.logger.Error("failed to store BEEF", "txid", result.TxID, "error", err)
		} else {
			resp.Stored = true
		}
	}

	// Add to local mempool
	if s.broadcaster != nil {
		if _, err := s.broadcaster.BroadcastBEEF(beefBytes); err != nil {
			s.logger.Error("mempool add failed", "txid", result.TxID, "error", err)
		} else {
			resp.Mempool = true
		}

		// Optional ARC submission
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

// handlePostData ingests a signed data envelope.
// POST /data
func (s *Server) handlePostData(w http.ResponseWriter, r *http.Request) {
	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "envelope store not configured")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"accepted": true,
		"topic":    env.Topic,
		"durable":  env.Durable,
		"key":      env.Key(),
	})
}

// handleQueryData queries envelopes by topic.
// GET /data?topic=...&limit=...
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

	limit := 100 // default
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
	}

	envs, err := s.envelopeStore.QueryByTopic(topic, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("query error: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"topic":     topic,
		"count":     len(envs),
		"envelopes": envs,
	})
}

// --- Overlay Endpoints ---

// handleOverlayLookup queries the overlay directory for SHIP peers by topic.
// GET /overlay/lookup?topic=...
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

// handleOverlayRegister ingests a SHIP script from an external source.
// POST /overlay/register
// Body: {"script": "<hex>", "txid": "<txid>", "output_index": <int>}
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

// handleOverlayDeregister removes a SHIP peer from the directory.
// POST /overlay/deregister
// Body: {"topic": "<topic>", "identity_pub": "<hex>"}
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

// --- Middleware ---

// requireAuth rejects requests without a valid bearer token.
// If no auth token is configured, ALL writes are rejected — secure by default.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" {
			writeError(w, http.StatusForbidden, "no auth token configured — write endpoints disabled")
			return
		}
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.authToken
		if auth != expected {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// --- Helpers ---

// readBEEF reads BEEF bytes from a request body, supporting both JSON
// ({"beef": "hex..."}) and raw binary Content-Type.
func readBEEF(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
