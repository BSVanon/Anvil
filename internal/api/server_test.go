package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"log/slog"
)

type gullibleTracker struct{}

func (g *gullibleTracker) IsValidRootForHeight(_ context.Context, _ *chainhash.Hash, _ uint32) (bool, error) {
	return true, nil
}
func (g *gullibleTracker) CurrentHeight(_ context.Context) (uint32, error) {
	return 999999, nil
}

func testServer(t *testing.T) *Server {
	t.Helper()

	// Header store
	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	// Proof store
	pdir, _ := os.MkdirTemp("", "anvil-api-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	validator := spv.NewValidator(hs)
	logger := slog.Default()
	return NewServer(hs, ps, validator, "test-token", logger)
}

func TestStatusEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["node"] != "anvil" {
		t.Fatalf("expected node=anvil, got %v", resp["node"])
	}
}

func TestHeadersTipEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/headers/tip", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["height"].(float64) != 0 {
		t.Fatalf("expected height 0, got %v", resp["height"])
	}
	if resp["hash"] == nil || resp["hash"] == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestValidateBEEFRequiresAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/tx/validate", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestValidateBEEFWithAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/tx/validate", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should not be 401 — might be 422 or 400 due to empty body
	if w.Code == http.StatusUnauthorized {
		t.Fatal("should not be 401 with valid token")
	}
}

func TestGetProofNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/tx/0000000000000000000000000000000000000000000000000000000000000000/proof", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetProofBadTxid(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/tx/short/proof", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
