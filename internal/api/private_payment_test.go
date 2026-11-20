package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// --- A payment never unlocks a `private` envelope ---
//
// These tests run against a charging configuration (payment_satoshis > 0, or
// a priced topic) and prove the authenticated/paid split in handlers.go,
// sse.go and payment.go: a verified x402 payment marks a request *paid*
// (isPaid, paid_context.go), never *authenticated* (isAuthed). Only
// isAuthed — this node's own operator bearer token, and nothing else —
// gates `private` envelope data and metadata. A validated app token is a
// separate, narrower credential that unlocks monetized PUBLIC content on
// its own topic only; it never gates `private` data. See
// docs/ANVIL_PRIVATE_FLAG_CONTRACT.md.

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
// a verified payment still unlocks a paid/monetized payload. The payment
// covers the envelope by its own monetization: one of its outputs pays the
// envelope's own payee at least its own price (envelopeForRequest,
// envelope_redaction.go). Here the envelope's payee is the script the proof
// pays.
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
			Model:                 envelope.MonetizationPassthrough,
			PayeeLockingScriptHex: testPayeeScript(t),
			PriceSats:             50,
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

// TestOperatorTokenUnlocksPrivateUnderChargingConfig: on a node where EVERY
// /data request genuinely owes a toll (route price > 0, not the earlier,
// vacuous PriceSats:0 config where this request was never actually charged
// anything), the operator bearer token still sees a `private` envelope in
// full, for free — no 402, no toll. Auth, not payment, is the
// private-envelope credential, and the operator is never charged on a read.
func TestOperatorTokenUnlocksPrivateUnderChargingConfig(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100) // every /data request owes 100 sats
	storePrivate(t, srv, `{"secret":"operator-sees-this"}`)

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

// TestTokenGatedWriteRoutesRequirePayment: a write route
// never skips the toll because ?topic= names a token-model topic — only the
// operator token or a real payment admits it. payment.go used to mark ANY
// such request "authenticated" with zero credential check, and write routes
// don't even wire a token gate, so nothing was ever verified at all.
func TestTokenGatedWriteRoutesRequirePayment(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	seedEnvelope(t, srv.envelopeStore, "writer:gated", &envelope.Monetization{
		Model:      envelope.MonetizationToken,
		AuthPubkey: appPubHex,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &DevNonceProvider{},
		Resolver:       resolver,
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	req1 := httptest.NewRequest("POST", "/data?topic=writer:gated", strings.NewReader(`{}`))
	req1.Host = "localhost"
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)
	if w1.Code != http.StatusPaymentRequired {
		t.Fatalf("POST /data on a token-model topic without payment must 402, got %d: %s", w1.Code, w1.Body.String())
	}

	req2 := httptest.NewRequest("POST", "/broadcast?topic=writer:gated", strings.NewReader("not-real-beef"))
	req2.Host = "localhost"
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusPaymentRequired {
		t.Fatalf("POST /broadcast on a token-model topic without payment must 402, got %d: %s", w2.Code, w2.Body.String())
	}
}

// TestPrivateOnlyMonetizedTopicNoExistenceOracle: a
// private-only topic whose latest (private) envelope happens to declare
// monetization must answer EXACTLY like a topic that doesn't exist at all —
// same price, same payee, no multi-payee list — so a 402 challenge can never
// be used to probe for a private-only topic's existence, payee, or price.
func TestPrivateOnlyMonetizedTopicNoExistenceOracle(t *testing.T) {
	srv := testServer(t)

	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "priv:monetized", Payload: `{"secret":"do-not-leak"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd", TTL: 60, Timestamp: 1700000000,
		Private: true,
		Monetization: &envelope.Monetization{
			Model:                 envelope.MonetizationPassthrough,
			PayeeLockingScriptHex: appPayeeScript(),
			PriceSats:             50,
		},
	})

	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	chPrivate := getChallenge(t, srv, "GET", "/data?topic=priv:monetized")
	chMissing := getChallenge(t, srv, "GET", "/data?topic=does:not:exist")

	if chPrivate.AmountSats != chMissing.AmountSats {
		t.Fatalf("private-only monetized topic leaked its price via 402: got %d, nonexistent-topic baseline is %d", chPrivate.AmountSats, chMissing.AmountSats)
	}
	if chPrivate.PayeeLockingScriptHex != chMissing.PayeeLockingScriptHex {
		t.Fatalf("private-only monetized topic leaked its payee script via 402: got %s, nonexistent-topic baseline is %s", chPrivate.PayeeLockingScriptHex, chMissing.PayeeLockingScriptHex)
	}
	if len(chPrivate.Payees) != 0 {
		t.Fatalf("private-only monetized topic leaked a multi-payee list: %v", chPrivate.Payees)
	}
}
