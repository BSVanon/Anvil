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

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
)

// Server is the Anvil REST API server.
type Server struct {
	headerStore *headers.Store
	proofStore  *spv.ProofStore
	validator   *spv.Validator
	broadcaster *txrelay.Broadcaster
	logger      *slog.Logger
	mux         *http.ServeMux
	authToken   string
}

// NewServer creates a new REST API server.
func NewServer(
	headerStore *headers.Store,
	proofStore *spv.ProofStore,
	validator *spv.Validator,
	broadcaster *txrelay.Broadcaster,
	authToken string,
	logger *slog.Logger,
) *Server {
	s := &Server{
		headerStore: headerStore,
		proofStore:  proofStore,
		validator:   validator,
		broadcaster: broadcaster,
		logger:      logger,
		mux:         http.NewServeMux(),
		authToken:   authToken,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Open read endpoints (per ARCHITECTURE.md Phase 8)
	s.mux.HandleFunc("GET /status", s.handleStatus)
	s.mux.HandleFunc("GET /headers/tip", s.handleHeadersTip)
	s.mux.HandleFunc("GET /tx/{txid}/beef", s.handleGetBEEF)

	// Authenticated write endpoints
	s.mux.HandleFunc("POST /broadcast", s.requireAuth(s.handleBroadcast))
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return s.mux
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
