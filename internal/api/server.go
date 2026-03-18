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
)

// Server is the Anvil REST API server.
type Server struct {
	headerStore *headers.Store
	proofStore  *spv.ProofStore
	validator   *spv.Validator
	logger      *slog.Logger
	mux         *http.ServeMux
	authToken   string
}

// NewServer creates a new REST API server.
func NewServer(
	headerStore *headers.Store,
	proofStore *spv.ProofStore,
	validator *spv.Validator,
	authToken string,
	logger *slog.Logger,
) *Server {
	s := &Server{
		headerStore: headerStore,
		proofStore:  proofStore,
		validator:   validator,
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

// handleGetBEEF serves a stored transaction as BEEF (raw tx + BUMP proof).
// GET /tx/:txid/beef
func (s *Server) handleGetBEEF(w http.ResponseWriter, r *http.Request) {
	txid := r.PathValue("txid")
	if len(txid) != 64 {
		writeError(w, http.StatusBadRequest, "txid must be 64 hex characters")
		return
	}

	rawTx, err := s.proofStore.GetRawTx(txid)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}

	bump, err := s.proofStore.GetBUMP(txid)
	if err != nil {
		// Have the raw tx but no proof — return what we have
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"txid":   txid,
			"raw_tx": hex.EncodeToString(rawTx),
			"bump":   nil,
			"proven": false,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"txid":   txid,
		"raw_tx": hex.EncodeToString(rawTx),
		"bump":   hex.EncodeToString(bump),
		"proven": true,
	})
}

// handleBroadcast is the core BEEF acceptance endpoint.
// POST /broadcast
//
// Per the architecture contract:
// 1. Parse BEEF
// 2. Validate merkle proofs against local header chain
// 3. Return a confidence level (spv_verified / partially_verified / unconfirmed)
// 4. Store the proven envelope for future serving
// 5. (Future: broadcast to peers, return broadcast-accepted)
//
// The confidence level tells the app how much trust to place in the transaction.
// The app decides what to do with it.
func (s *Server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	beefBytes, err := readBEEF(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate BEEF against local headers — returns confidence level
	result, err := s.validator.ValidateBEEF(context.Background(), beefBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("validation error: %v", err))
		return
	}

	if result.Confidence == spv.ConfidenceInvalid {
		writeJSON(w, http.StatusUnprocessableEntity, result)
		return
	}

	// Only store if we have at least some verification
	if result.Confidence == spv.ConfidenceSPVVerified || result.Confidence == spv.ConfidencePartiallyVerified {
		txid, err := s.proofStore.StoreFromBEEF(beefBytes)
		if err != nil {
			s.logger.Error("failed to store BEEF", "txid", result.TxID, "error", err)
			// Don't fail the request — validation succeeded, storage is secondary
		} else {
			s.logger.Info("stored BEEF",
				"txid", txid,
				"confidence", result.Confidence,
			)
		}
	}

	// TODO: Phase 3 — broadcast raw tx to connected peers
	// When broadcast is implemented, upgrade confidence to broadcast-accepted
	// if peers accept the transaction into mempool.

	writeJSON(w, http.StatusOK, result)
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
