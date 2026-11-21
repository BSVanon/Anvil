package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// TestContentServer_ReturnsSharedInstance confirms the gateway mechanism's
// content seam hook returns the SAME content server NewServer already
// constructed (its warm cache, fetch and txid check) — not nil, and not a
// second, independent instance.
func TestContentServer_ReturnsSharedInstance(t *testing.T) {
	s := testServer(t)
	cs := s.ContentServer()
	if cs == nil {
		t.Fatal("expected a non-nil content server")
	}
	if s.ContentServer() != cs {
		t.Fatal("expected ContentServer to always return the same instance")
	}
}

// TestSetGatewayStats_MergedIntoStats confirms the /stats hook's
// aggregate gateway counters surface through.
func TestSetGatewayStats_MergedIntoStats(t *testing.T) {
	s := testServer(t)
	s.SetGatewayStats(func() map[string]int64 {
		return map[string]int64{"gateway_requests": 42}
	})

	req := httptest.NewRequest("GET", "/stats", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode /stats: %v", err)
	}
	gw, ok := body["gateway"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a \"gateway\" object in /stats, got %#v", body["gateway"])
	}
	if got := gw["gateway_requests"]; got != float64(42) {
		t.Fatalf("expected gateway_requests=42, got %v", got)
	}
}

// TestSetGatewayStats_NilOmitsField confirms /stats carries no "gateway"
// field at all when no hook is registered — a standard node's /stats stays
// byte-for-byte what it is today.
func TestSetGatewayStats_NilOmitsField(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/stats", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode /stats: %v", err)
	}
	if _, ok := body["gateway"]; ok {
		t.Fatal("expected no \"gateway\" field when SetGatewayStats was never called")
	}
}
