package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCors_AllowsCanonicalOverlayHeaders is the integration test
// Codex review 2968609c62a2eb51 asked for: exercise the real cors()
// helper that backs Server.CorsWrap and assert the canonical custom
// headers (x-includes-off-chain-values, x-aggregation) appear in
// Access-Control-Allow-Headers. Without these, browser preflight
// rejects the real /submit + /lookup requests before they reach the
// canonical engine even though the routes themselves are CORS-wrapped.
//
// Canonical custom headers per ts-stack/specs/overlay/overlay-http.yaml:
//   - x-topics                       — /submit topic list
//   - x-includes-off-chain-values    — /submit opt-in for prefixed body
//   - x-aggregation                  — /lookup opt-in for binary response
//
// Plus the existing Anvil custom headers must still be present.
func TestCors_AllowsCanonicalOverlayHeaders(t *testing.T) {
	// Wrap a sentinel handler with cors() and exercise it via httptest.
	// This is functionally identical to what Server.CorsWrap does, so
	// the test stays focused on the cors() output rather than spinning
	// up a full Server with its many dependencies.
	wrapped := cors(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)

	// OPTIONS preflight — what a browser sends before a cross-origin
	// /submit or /lookup with the canonical custom headers.
	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/", nil)
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, x-topics, x-includes-off-chain-values, x-aggregation")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS preflight: %v", err)
	}
	defer resp.Body.Close()

	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	if allowHeaders == "" {
		t.Fatalf("Access-Control-Allow-Headers missing on OPTIONS response")
	}

	canonical := []string{
		"x-topics",
		"x-includes-off-chain-values",
		"x-aggregation",
		"x-bsv-topic", // W-10.3 GASP routes (/requestSyncResponse, /requestForeignGASPNode)
	}
	lowered := strings.ToLower(allowHeaders)
	for _, name := range canonical {
		if !strings.Contains(lowered, strings.ToLower(name)) {
			t.Fatalf("Access-Control-Allow-Headers missing canonical header %q (got %q)", name, allowHeaders)
		}
	}

	// Sanity check: existing Anvil custom headers must still be in
	// the allow-list (we don't want this fix to silently break legacy
	// browser callers).
	for _, name := range []string{
		"Content-Type",
		"Authorization",
		"X-App-Token",
		"X-Anvil-Auth",
		"X402-Proof",
		"X-Bsv-Payment",
	} {
		if !strings.Contains(lowered, strings.ToLower(name)) {
			t.Fatalf("Access-Control-Allow-Headers dropped pre-existing header %q (got %q)", name, allowHeaders)
		}
	}

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("OPTIONS preflight returned status %d, want 204", resp.StatusCode)
	}
}

// TestCors_AllowsGASPPreflight pins the W-10.3 federation surface
// against browser CORS preflight. The canonical /requestSyncResponse
// and /requestForeignGASPNode routes (handlers_gasp.go) require an
// X-BSV-Topic header per the upstream OpenAPI spec; without it in
// Access-Control-Allow-Headers, a browser-side LookupResolver running
// against an Anvil host would fail preflight before the request even
// reached the canonical handler. Codex review 6daa58cb1a6f43e4 caught
// the original cors() omitting X-BSV-Topic.
func TestCors_AllowsGASPPreflight(t *testing.T) {
	wrapped := cors(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/requestSyncResponse", nil)
	req.Header.Set("Origin", "https://example.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, X-BSV-Topic")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS preflight for GASP route: %v", err)
	}
	defer resp.Body.Close()

	allowHeaders := strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers"))
	if !strings.Contains(allowHeaders, "x-bsv-topic") {
		t.Fatalf("Access-Control-Allow-Headers missing X-BSV-Topic for GASP preflight (got %q)", resp.Header.Get("Access-Control-Allow-Headers"))
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("GASP preflight returned status %d, want 204", resp.StatusCode)
	}
}

// TestCors_AppliesHeadersToNonOptionsTraffic verifies the wrap also
// stamps the Allow-* headers on real (non-OPTIONS) responses, since
// browsers check them after the preflight succeeds. Without these on
// the actual response, the browser still treats the request as
// cross-origin-blocked.
func TestCors_AppliesHeadersToNonOptionsTraffic(t *testing.T) {
	wrapped := cors(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", bytes.NewReader([]byte("body")))
	req.Header.Set("Origin", "https://example.test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("Allow-Origin missing on POST response")
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers")), "x-includes-off-chain-values") {
		t.Fatalf("Allow-Headers missing canonical custom header on POST response")
	}
}
