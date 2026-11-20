package api

import (
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

// --- A validated X-App-Token unlocks monetized PUBLIC content on exactly
// the topic it was checked against, and nothing else ---
//
// These tests prove appTokenTopicMatches (app_token_context.go) and its
// callers in handlers.go and payment.go: a validated app token is a
// credential for monetized public content on its own exact topic only. It
// never gates `private` envelope data (only isAuthed does — auth.go) and
// never widens to a different or prefix-related topic. See
// docs/ANVIL_PRIVATE_FLAG_CONTRACT.md.

// TestAppTokenDoesNotUnlockPrivateEnvelope: a `private` envelope on a
// token-gated (Model 4) topic is NOT served by a caller presenting a valid,
// signature-verified X-App-Token. Only this node's operator token unlocks
// `private` data — an app token is a credential for monetized PUBLIC
// content on the topic it was validated for, nothing more. The topic is
// "mixed" (a public envelope carries the Model 4 declaration a real app
// would publish; a newer private envelope carries a secret) so the token
// gate still has something public to validate against — proving the app
// token DOES unlock the topic's public content (the toll is skipped) while
// the private envelope on that same topic stays invisible regardless.
func TestAppTokenDoesNotUnlockPrivateEnvelope(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	const pub = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"

	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "appgated:mixed", Payload: `{"tier":"public"}`,
		Pubkey: pub, Signature: "3045022100abcd", TTL: 60, Timestamp: 1700000000,
		Monetization: &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex},
	})
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "appgated:mixed", Payload: `{"secret":"app-token-must-not-see-this"}`,
		Pubkey: pub, Signature: "3045022100abcd", TTL: 60, Timestamp: 1700000001,
		Private: true,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore) // charging configuration
	srv.mux = http.NewServeMux()
	srv.routes()

	ts := fmt.Sprintf("%d", time.Now().Unix())
	digest := sha256.Sum256([]byte("appgated:mixed:" + ts))
	sig, _ := appKey.Sign(digest[:])
	token := hex.EncodeToString(sig.Serialize()) + ":" + ts

	req := httptest.NewRequest("GET", "/data?topic=appgated:mixed&limit=10", nil)
	req.Host = "localhost"
	req.Header.Set("X-App-Token", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (toll skipped) with a valid app token for this topic, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count     int                      `json:"count"`
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Count != 1 {
		t.Fatalf("expected only the public envelope to be visible, got count=%d", resp.Count)
	}
	if p, _ := resp.Envelopes[0]["payload"].(string); strings.Contains(p, "app-token-must-not-see-this") {
		t.Fatal("a valid app token must NOT unlock a private envelope, even on its own topic")
	}
}

// TestAppTokenNeverUnlocksPrivateOrOtherTopics: a self-issued
// app token — minted from an envelope the caller published declaring their
// OWN pubkey as the topic's AuthPubkey — is a valid credential for that one
// topic and nothing else. It must not unlock a private envelope on a
// different topic, and it must not interfere with the operator's own,
// separate bearer-token access: not to the private topic, and not even to
// the attacker's own token-gated topic, which the operator must be able to
// read with no X-App-Token at all (no 401 lockout).
func TestAppTokenNeverUnlocksPrivateOrOtherTopics(t *testing.T) {
	srv := testServer(t)

	attackerKey, _ := ec.NewPrivateKey()
	attackerPubHex := hex.EncodeToString(attackerKey.PubKey().Compressed())
	seedEnvelope(t, srv.envelopeStore, "attacker:cheap", &envelope.Monetization{
		Model:      envelope.MonetizationToken,
		AuthPubkey: attackerPubHex,
	})
	storePrivate(t, srv, `{"secret":"operator-only"}`) // lacriada:household-x

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:        0, // node itself is free; only the attacker's own topic is token-gated
		NonceProvider:    &DevNonceProvider{},
		Resolver:         resolver,
		AllowPassthrough: true,
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	ts := fmt.Sprintf("%d", time.Now().Unix())
	digest := sha256.Sum256([]byte("attacker:cheap:" + ts))
	sig, _ := attackerKey.Sign(digest[:])
	token := hex.EncodeToString(sig.Serialize()) + ":" + ts

	// The self-issued token validates on its own, self-declared topic...
	req1 := httptest.NewRequest("GET", "/data?topic=attacker:cheap", nil)
	req1.Host = "localhost"
	req1.Header.Set("X-App-Token", token)
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("self-issued token should validate on its own topic, got %d: %s", w1.Code, w1.Body.String())
	}

	// ...but presented against the PRIVATE topic it unlocks nothing.
	req2 := httptest.NewRequest("GET", "/data?topic=lacriada:household-x&limit=10", nil)
	req2.Host = "localhost"
	req2.Header.Set("X-App-Token", token)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp2 struct {
		Count int `json:"count"`
	}
	json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2.Count != 0 {
		t.Fatalf("an app token for a different topic must not unlock a private envelope; got count=%d", resp2.Count)
	}

	// The operator's own bearer read still works after the attacker's
	// envelope — on the private topic...
	envs := queryPrivateTopic(t, srv, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer test-token")
	})
	if len(envs) != 1 {
		t.Fatalf("operator bearer read must still work after the attacker's envelope; got %d", len(envs))
	}

	// ...and on the token-gated topic too, with no X-App-Token at all — no
	// 401 lockout.
	req4 := httptest.NewRequest("GET", "/data?topic=attacker:cheap", nil)
	req4.Host = "localhost"
	req4.Header.Set("Authorization", "Bearer test-token")
	w4 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("operator bearer token must read a token-gated topic without X-App-Token (no lockout), got %d: %s", w4.Code, w4.Body.String())
	}
}

// TestAppTokenDoesNotUnredactPrefixSubtopic: a validated app token for
// topic A does not unredact a DIFFERENT, merely-prefix-related topic B's
// monetized content, even when the same GET /data query returns both in
// one response. The store's prefix scan (QueryByTopic) returns B alongside
// A when B's name happens to extend A's with ":" — a separate, already
// known gap this test treats as a given, not something it fixes — but
// appTokenTopicMatches must still do an exact comparison per envelope, so
// B's own price stays enforced regardless of A's validated token.
func TestAppTokenDoesNotUnredactPrefixSubtopic(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())

	const parent = "handlerprefix:parent"
	const child = "handlerprefix:parent:extra"

	seedEnvelope(t, srv.envelopeStore, parent, &envelope.Monetization{
		Model: envelope.MonetizationToken, AuthPubkey: appPubHex,
	})
	seedEnvelope(t, srv.envelopeStore, child, &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 50,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	ts := fmt.Sprintf("%d", time.Now().Unix())
	digest := sha256.Sum256([]byte(parent + ":" + ts))
	sig, _ := appKey.Sign(digest[:])
	token := hex.EncodeToString(sig.Serialize()) + ":" + ts

	req := httptest.NewRequest("GET", "/data?topic="+parent+"&limit=10", nil)
	req.Host = "localhost"
	req.Header.Set("X-App-Token", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (token validates on its own topic), got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Count     int                      `json:"count"`
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 {
		t.Fatalf("expected the prefix scan to return both the parent and child envelope (a known, separate gap this test treats as a given), got count=%d", resp.Count)
	}

	for _, e := range resp.Envelopes {
		topic, _ := e["topic"].(string)
		payload, _ := e["payload"].(string)
		switch topic {
		case parent:
			if strings.Contains(payload, "paid content") {
				t.Fatalf("the parent envelope, on the token's own validated topic, should not be redacted: %v", e)
			}
		case child:
			if !strings.Contains(payload, "paid content") {
				t.Fatalf("a token validated for %q must not unredact the differently-named topic %q, even though the same query returned it: %v", parent, child, e)
			}
		default:
			t.Fatalf("unexpected topic in response: %q", topic)
		}
	}
}
