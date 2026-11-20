package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// --- B3: a payment never unlocks a `private` envelope ---
//
// These tests run against a charging configuration (payment_satoshis > 0, or
// a priced topic) and prove the authenticated/paid split in handlers.go,
// sse.go and payment.go: a verified x402 payment marks a request *paid*
// (isPaid, paid_context.go), never *authenticated* (isAuthed). Only isAuthed
// — the operator bearer token or a valid app token — gates `private`
// envelope data and metadata. See docs/ANVIL_PRIVATE_FLAG_CONTRACT.md.

// queryWithProof submits a GET to path with a valid x402 proof attached and
// returns the decoded /data response. t.Fatal on anything but 200.
func queryWithProof(t *testing.T, srv *Server, path string, ch *X402Challenge, proofB64 string) (count int, envs []map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after valid payment, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count     int                      `json:"count"`
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Count, resp.Envelopes
}

// TestPaidRequestOmitsPrivateEnvelope: under a flat per-request charge, a
// caller who completes a real x402 payment for GET /data sees a private
// topic exactly as an unauthenticated caller would — empty, not unlocked by
// paying the node's toll.
func TestPaidRequestOmitsPrivateEnvelope(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`) // lacriada:household-x

	path := "/data?topic=lacriada:household-x&limit=10"
	ch := getChallenge(t, srv, "GET", path)
	proofB64 := buildProof(t, ch, 200, testPayeeScript(t))

	count, envs := queryWithProof(t, srv, path, ch, proofB64)
	if count != 0 || len(envs) != 0 {
		t.Fatalf("a verified payment must NOT unlock a private envelope; got count=%d envelopes=%v", count, envs)
	}
}

// TestPaidRequestStillUnlocksMonetizedPayload: preserves pre-split behavior —
// a verified payment still unlocks a paid/monetized payload, exactly as
// isAuthedOrPaid intends (the payment does not have to target this specific
// envelope's own monetization; it is the same node-level admission payment
// that already gated entry to the handler).
func TestPaidRequestStillUnlocksMonetizedPayload(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type:      "data",
		Topic:     "test:paid-via-toll",
		Payload:   `{"secret":"should-be-visible-after-payment"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd",
		TTL:       60,
		Timestamp: 1700000000,
		Monetization: &envelope.Monetization{
			Model:     envelope.MonetizationPassthrough,
			PriceSats: 50,
		},
	})

	path := "/data?topic=test:paid-via-toll&limit=1"
	ch := getChallenge(t, srv, "GET", path)
	proofB64 := buildProof(t, ch, 200, testPayeeScript(t))

	count, envs := queryWithProof(t, srv, path, ch, proofB64)
	if count != 1 || len(envs) != 1 {
		t.Fatalf("expected the monetized envelope, got count=%d envelopes=%v", count, envs)
	}
	payload, _ := envs[0]["payload"].(string)
	if strings.Contains(payload, "paid content") {
		t.Fatalf("a verified payment should still unlock paid content, got redaction placeholder: %s", payload)
	}
	if !strings.Contains(payload, "should-be-visible-after-payment") {
		t.Fatalf("expected full payload after payment, got: %s", payload)
	}
}

// TestOperatorTokenUnlocksPrivateUnderChargingConfig: on a node that is in a
// genuine charging configuration (a priced topic elsewhere, payment gate
// active), the operator bearer token still sees a `private` envelope on an
// unpriced topic in full — auth, not payment, is the private-envelope
// credential.
func TestOperatorTokenUnlocksPrivateUnderChargingConfig(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"operator-sees-this"}`) // lacriada:household-x, unpriced
	seedEnvelope(t, srv.envelopeStore, "priced:other", &envelope.Monetization{
		Model:                 envelope.MonetizationPassthrough,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             50,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:        0, // node itself is free; priced:other is charged via its own monetization
		NonceProvider:    &DevNonceProvider{},
		Resolver:         resolver,
		AllowPassthrough: true,
	})
	srv.mux = http.NewServeMux()
	srv.routes()
	if srv.paymentGate == nil {
		t.Fatal("expected a charging configuration (gate must exist)")
	}

	envs := queryPrivateTopic(t, srv, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer test-token")
	})
	if len(envs) != 1 {
		t.Fatalf("operator bearer token should still see the private envelope under a charging config; got %d", len(envs))
	}
	if p, _ := envs[0]["payload"].(string); !strings.Contains(p, "operator-sees-this") {
		t.Fatalf("expected full private payload, got: %v", envs[0]["payload"])
	}
}

// TestAppTokenUnlocksPrivateEnvelope: a `private` envelope on a token-gated
// (Model 4) topic is served in full to a caller presenting a valid,
// signature-verified X-App-Token — the other credential the contract allows
// — with the payment gate also active (charging configuration).
func TestAppTokenUnlocksPrivateEnvelope(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())

	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type:      "data",
		Topic:     "appgated:private",
		Payload:   `{"secret":"app-token-sees-this"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd",
		TTL:       60,
		Timestamp: 1700000000,
		Private:   true,
		Monetization: &envelope.Monetization{
			Model:      envelope.MonetizationToken,
			AuthPubkey: appPubHex,
		},
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore) // charging configuration
	srv.mux = http.NewServeMux()
	srv.routes()

	ts := fmt.Sprintf("%d", time.Now().Unix())
	digest := sha256.Sum256([]byte("appgated:private:" + ts))
	sig, _ := appKey.Sign(digest[:])
	token := hex.EncodeToString(sig.Serialize()) + ":" + ts

	req := httptest.NewRequest("GET", "/data?topic=appgated:private&limit=10", nil)
	req.Host = "localhost"
	req.Header.Set("X-App-Token", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid app token, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count     int                      `json:"count"`
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 1 {
		t.Fatalf("app token should see the private envelope; got count %d", resp.Count)
	}
	if p, _ := resp.Envelopes[0]["payload"].(string); !strings.Contains(p, "app-token-sees-this") {
		t.Fatalf("expected full private payload, got: %v", resp.Envelopes[0]["payload"])
	}
}

// TestSpoofedPaidMarkerIgnoredUnderChargingConfig: under a charging
// configuration (a priced topic elsewhere, payment gate active), a
// client-supplied header guessing at a "paid" marker name does not unlock a
// private envelope on an unpriced topic — there is no header for this
// signal at all (see paid_context.go, isPaid), so nothing a client sends can
// set it. (TestPaidPayloadSpoofedAnvilAuthedIgnored, in redaction_test.go,
// covers the companion monetized-payload half of this property.)
func TestSpoofedPaidMarkerIgnoredUnderChargingConfig(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`) // lacriada:household-x, unpriced
	seedEnvelope(t, srv.envelopeStore, "priced:other", &envelope.Monetization{
		Model:                 envelope.MonetizationPassthrough,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             50,
	})
	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:        0,
		NonceProvider:    &DevNonceProvider{},
		Resolver:         resolver,
		AllowPassthrough: true,
	})
	srv.mux = http.NewServeMux()
	srv.routes()
	if srv.paymentGate == nil {
		t.Fatal("expected a charging configuration (gate must exist)")
	}

	envs := queryPrivateTopic(t, srv, func(r *http.Request) {
		r.Header.Set("X-Anvil-Paid", "true") // spoof attempt — no such signal exists
		r.Header.Set("X-Anvil-Authed", "true")
	})
	if len(envs) != 0 {
		t.Fatalf("spoofed headers must not unlock the private envelope; got %d", len(envs))
	}
}

// TestSubscribePaidRequestOmitsPrivateEnvelope: /data/subscribe (SSE) follows
// the same rule as GET /data — a verified payment never streams a private
// envelope to the paying subscriber.
func TestSubscribePaidRequestOmitsPrivateEnvelope(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)

	path := "/data/subscribe?topic=sse:private"
	ch := getChallenge(t, srv, "GET", path)
	proofB64 := buildProof(t, ch, 200, testPayeeScript(t))

	req := httptest.NewRequest("GET", path, nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "sse:private",
		Payload:   `{"secret":"sse-leak-check"}`,
		Timestamp: time.Now().Unix(),
		Private:   true,
	}
	env.Sign(key)
	srv.NotifyEnvelope(env)

	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if strings.Contains(w.Body.String(), "sse-leak-check") {
		t.Fatal("a verified payment must not stream a private envelope over /data/subscribe")
	}
}
