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
	// Open read endpoints
	s.mux.HandleFunc("GET /status", s.handleStatus)
	s.mux.HandleFunc("GET /headers/tip", s.handleHeadersTip)
	s.mux.HandleFunc("GET /tx/{txid}/proof", s.handleGetProof)

	// Authenticated write endpoints
	s.mux.HandleFunc("POST /tx/validate", s.requireAuth(s.handleValidateBEEF))
	s.mux.HandleFunc("POST /tx/store", s.requireAuth(s.handleStoreBEEF))
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// --- Handlers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	tip := s.headerStore.Tip()
	resp := map[string]interface{}{
		"node":    "anvil",
		"version": "0.1.0",
		"headers": map[string]interface{}{
			"height": tip,
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

func (s *Server) handleGetProof(w http.ResponseWriter, r *http.Request) {
	txid := r.PathValue("txid")
	if len(txid) != 64 {
		writeError(w, http.StatusBadRequest, "txid must be 64 hex characters")
		return
	}

	bump, err := s.proofStore.GetBUMP(txid)
	if err != nil {
		writeError(w, http.StatusNotFound, "no proof found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"txid": txid,
		"bump": hex.EncodeToString(bump),
	})
}

func (s *Server) handleValidateBEEF(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	// Accept hex-encoded BEEF in JSON body or raw binary
	var beefBytes []byte
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		var req struct {
			Beef string `json:"beef"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		beefBytes, err = hex.DecodeString(req.Beef)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid hex in beef field")
			return
		}
	} else {
		beefBytes = body
	}

	result, err := s.validator.ValidateBEEF(context.Background(), beefBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("validation error: %v", err))
		return
	}

	status := http.StatusOK
	if !result.Valid {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, result)
}

func (s *Server) handleStoreBEEF(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var beefBytes []byte
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		var req struct {
			Beef string `json:"beef"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		beefBytes, err = hex.DecodeString(req.Beef)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid hex in beef field")
			return
		}
	} else {
		beefBytes = body
	}

	// Validate first
	result, err := s.validator.ValidateBEEF(context.Background(), beefBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("validation error: %v", err))
		return
	}
	if !result.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, result)
		return
	}

	// Store
	txid, err := s.proofStore.StoreFromBEEF(beefBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("store error: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"txid":    txid,
		"stored":  true,
		"message": result.Message,
	})
}

// --- Middleware ---

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" {
			next(w, r)
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
