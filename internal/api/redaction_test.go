package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestPaidPayloadRedactedForPublicReads(t *testing.T) {
	srv := testServer(t)

	// Ingest an envelope with monetization
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:paid",
		Payload:   `{"secret":"do-not-leak"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd",
		TTL:       60,
		Timestamp: 1700000000,
		Monetization: &envelope.Monetization{
			Model:    "passthrough",
			PriceSats: 50,
		},
	}
	srv.envelopeStore.StoreEphemeralDirect(env)

	// Public read (no auth) — payload should be redacted
	req := httptest.NewRequest("GET", "/data?topic=test:paid&limit=1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Envelopes []struct {
			Payload string `json:"payload"`
		} `json:"envelopes"`
	}
	json.NewDecoder(w.Body).Decode(&resp)

	if len(resp.Envelopes) == 0 {
		t.Fatal("expected at least 1 envelope")
	}
	if strings.Contains(resp.Envelopes[0].Payload, "do-not-leak") {
		t.Fatal("paid payload should be redacted for public reads")
	}
	if !strings.Contains(resp.Envelopes[0].Payload, "paid content") {
		t.Fatalf("expected redaction placeholder, got: %s", resp.Envelopes[0].Payload)
	}
}

func TestPaidPayloadVisibleForAuthenticatedReads(t *testing.T) {
	srv := testServer(t)

	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:paid",
		Payload:   `{"secret":"should-be-visible"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd",
		TTL:       60,
		Timestamp: 1700000000,
		Monetization: &envelope.Monetization{
			Model:    "passthrough",
			PriceSats: 50,
		},
	}
	srv.envelopeStore.StoreEphemeralDirect(env)

	// Authenticated read (bearer token) — payload should be full
	req := httptest.NewRequest("GET", "/data?topic=test:paid&limit=1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Envelopes []struct {
			Payload string `json:"payload"`
		} `json:"envelopes"`
	}
	json.NewDecoder(w.Body).Decode(&resp)

	if len(resp.Envelopes) == 0 {
		t.Fatal("expected at least 1 envelope")
	}
	if !strings.Contains(resp.Envelopes[0].Payload, "should-be-visible") {
		t.Fatalf("authenticated read should see full payload, got: %s", resp.Envelopes[0].Payload)
	}
}

func TestPaidRedactionDoesNotMutateStore(t *testing.T) {
	srv := testServer(t)

	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:paid",
		Payload:   `{"original":"data"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd",
		TTL:       60,
		Timestamp: 1700000000,
		Monetization: &envelope.Monetization{
			Model:    "passthrough",
			PriceSats: 50,
		},
	}
	srv.envelopeStore.StoreEphemeralDirect(env)

	// Public read — triggers redaction
	req := httptest.NewRequest("GET", "/data?topic=test:paid&limit=1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Now authenticated read — should still see original
	req2 := httptest.NewRequest("GET", "/data?topic=test:paid&limit=1", nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	var resp struct {
		Envelopes []struct {
			Payload string `json:"payload"`
		} `json:"envelopes"`
	}
	json.NewDecoder(w2.Body).Decode(&resp)

	if len(resp.Envelopes) == 0 {
		t.Fatal("expected at least 1 envelope")
	}
	if !strings.Contains(resp.Envelopes[0].Payload, "original") {
		t.Fatal("store should not be mutated by public redaction — authenticated read got: " + resp.Envelopes[0].Payload)
	}
}
