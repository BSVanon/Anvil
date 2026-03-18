package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
)

func testServer(t *testing.T) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

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

// testServerNoAuth creates a server with no auth token configured.
func testServerNoAuth(t *testing.T) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-api-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	validator := spv.NewValidator(hs)
	logger := slog.Default()
	return NewServer(hs, ps, validator, "", logger) // empty token
}

// --- Open read endpoints ---

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
	h := resp["headers"].(map[string]interface{})
	if h["height"].(float64) != 0 {
		t.Fatalf("expected height 0, got %v", h["height"])
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

func TestGetBEEFNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/tx/0000000000000000000000000000000000000000000000000000000000000000/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetBEEFBadTxid(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/tx/short/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- Auth ---

func TestBroadcastRequiresAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBroadcastWithValidAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("garbage"))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should not be 401 — will be 422 due to invalid BEEF
	if w.Code == http.StatusUnauthorized {
		t.Fatal("should not be 401 with valid token")
	}
}

func TestBroadcastRejectsInvalidBEEF(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("not beef at all"))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}

	var result spv.Result
	json.NewDecoder(w.Body).Decode(&result)
	if result.Confidence != spv.ConfidenceInvalid {
		t.Fatalf("expected confidence=invalid, got %s", result.Confidence)
	}
}

func TestBroadcastReturnsConfidenceLevel(t *testing.T) {
	srv := testServer(t)
	// Send invalid BEEF — should get a confidence level in the response
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("bad beef"))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var result spv.Result
	json.NewDecoder(w.Body).Decode(&result)
	if result.Confidence == "" {
		t.Fatal("expected a confidence level in the response")
	}
}

// --- Auth default: no token = writes disabled ---

func TestBroadcastDisabledWithNoToken(t *testing.T) {
	srv := testServerNoAuth(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("anything"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when no auth token configured, got %d", w.Code)
	}
}

// --- JSON body parsing ---

func TestBroadcastAcceptsJSON(t *testing.T) {
	srv := testServer(t)
	body := `{"beef": "deadbeef"}`
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should parse the JSON and attempt to validate the hex
	// deadbeef is not valid BEEF, so expect 422
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBroadcastEmptyBody(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", w.Code)
	}
}
