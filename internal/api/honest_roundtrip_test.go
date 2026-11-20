package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// --- Item 5: a full honest payment round trip, through both ways a client
// can pay (the x402 challenge/proof flow and the simpler X-Bsv-Payment
// direct-payment header), after every item 1-9 hardening change in this
// brick. Every other test in this package's x402 surface is adversarial —
// this is the one that proves a legitimate payer is never collateral
// damage from any of it: the body-read-before-reserve ordering (item 1),
// the budget-bounded nonce mint (item 3), direct-payment input
// verification (item 4), and exact-topic resolution/redaction (items 6, 8,
// 9) all still let a real payer through to their own, correctly-priced
// content, unredacted, and still deny it before payment. ---

// TestHonestChallengeProofRoundTripUnlocksExactTopic: GET /data?topic=X on
// a passthrough-priced topic — 402 with the topic's own price and payee,
// pay it, 200 with the topic's own payload unredacted.
func TestHonestChallengeProofRoundTripUnlocksExactTopic(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "news:premium", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 250,
	})
	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore) // node itself is free; only the topic charges
	srv.mux = http.NewServeMux()
	srv.routes()

	path := "/data?topic=news:premium"

	// Denied before payment.
	unpaidReq := httptest.NewRequest("GET", path, nil)
	unpaidReq.Host = "localhost"
	unpaidW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(unpaidW, unpaidReq)
	if unpaidW.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 before payment, got %d: %s", unpaidW.Code, unpaidW.Body.String())
	}

	ch := getChallenge(t, srv, "GET", path)
	if ch.AmountSats != 250 || ch.PayeeLockingScriptHex != appPayeeScript() {
		t.Fatalf("expected the topic's own 250-sat challenge to its own payee, got amount=%d payee=%s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}

	proofB64 := buildProof(t, ch, 250, appPayeeScript())
	_, envs := queryWithProof(t, srv, path, ch, proofB64)

	found := false
	for _, e := range envs {
		if e["topic"] != "news:premium" {
			continue
		}
		found = true
		payload, _ := e["payload"].(string)
		if strings.Contains(payload, "paid content") {
			t.Fatalf("an honest payment for this exact topic must unlock its own payload, got: %s", payload)
		}
	}
	if !found {
		t.Fatal("expected news:premium in the response after payment")
	}
}

// TestHonestDirectPaymentRoundTripUnlocksExactTopic: the same topic and
// price, paid instead via a real signed transaction in the X-Bsv-Payment
// header (Calhooon-compatible direct-payment flow, payment_verify.go) —
// item 4's verifyDirectPaymentInputs must accept it on the strength of its
// own genuine signature, same as the challenge/proof case above, and the
// exact-topic paid context (item 6) must unlock exactly this topic's own
// payload here too.
func TestHonestDirectPaymentRoundTripUnlocksExactTopic(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "news:premium", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 250,
	})
	gate := testGateWithAppPayments(t, 0, srv.envelopeStore)
	gate.arcClient = mockARCServer(t)
	srv.paymentGate = gate
	srv.mux = http.NewServeMux()
	srv.routes()

	path := "/data?topic=news:premium"

	tx := buildSignedDirectPaymentTx(t, appPayeeScript(), 250)
	efHex, err := tx.EFHex()
	if err != nil {
		t.Fatalf("serialize signed tx as extended format: %v", err)
	}

	req := httptest.NewRequest("GET", path, nil)
	req.Host = "localhost"
	req.Header.Set(HeaderBSVPayment, efHex)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after a genuine signed direct payment, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get(HeaderX402Receipt) == "" {
		t.Fatal("expected an X402 receipt header on a successful direct payment")
	}

	var resp struct {
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /data response: %v", err)
	}
	found := false
	for _, e := range resp.Envelopes {
		if e["topic"] != "news:premium" {
			continue
		}
		found = true
		payload, _ := e["payload"].(string)
		if strings.Contains(payload, "paid content") {
			t.Fatalf("an honest direct payment for this exact topic must unlock its own payload, got: %s", payload)
		}
	}
	if !found {
		t.Fatal("expected news:premium in the response after direct payment")
	}
}

// TestHonestPaymentDoesNotLeakSiblingTopic: the same payment flow that
// unlocked news:premium above, made for topic news, unlocks news's own
// payload and never serves the pricier sub-topic news:premium: a read of
// topic news returns news only.
func TestHonestPaymentDoesNotLeakSiblingTopic(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "news", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: testPayeeScript(t), PriceSats: 5,
	})
	seedEnvelope(t, srv.envelopeStore, "news:premium", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 250,
	})
	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	path := "/data?topic=news"
	ch := getChallenge(t, srv, "GET", path)
	if ch.AmountSats != 5 {
		t.Fatalf("expected news's own 5-sat price, got %d", ch.AmountSats)
	}
	proofB64 := buildProof(t, ch, 5, testPayeeScript(t))
	_, envs := queryWithProof(t, srv, path, ch, proofB64)

	if len(envs) != 1 || envs[0]["topic"] != "news" {
		t.Fatalf("a read of topic news must return news's own envelope only, never news:premium; got: %v", envs)
	}
	if newsPayload, _ := envs[0]["payload"].(string); strings.Contains(newsPayload, "paid content") {
		t.Fatalf("the honest 5-sat payment must unlock news's own payload, got: %s", newsPayload)
	}
}
