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
	storePrivate(t, srv, `{"secret":"operator-only"}`) // app:private-x

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
	req2 := httptest.NewRequest("GET", "/data?topic=app:private-x&limit=10", nil)
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
// monetized content, even when B is token-gated by the same key, so only the
// topic tells the two apart. A GET /data query on A returns A's own envelopes
// only, never B's, though B's name extends A's with ":". A query on B
// carrying A's token is refused by the token gate, which binds the token's
// signature to the topic it was signed for. And a request for B whose context
// carries the token validated for A, which the gate itself cannot produce,
// still leaves B's payload redacted, because a token unlocks only its own
// exact topic (appTokenTopicMatches).
func TestAppTokenDoesNotUnredactPrefixSubtopic(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())

	const parent = "handlerprefix:parent"
	const child = "handlerprefix:parent:extra"

	for _, topic := range []string{parent, child} {
		seedEnvelope(t, srv.envelopeStore, topic, &envelope.Monetization{
			Model: envelope.MonetizationToken, AuthPubkey: appPubHex,
		})
	}

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	ts := fmt.Sprintf("%d", time.Now().Unix())
	digest := sha256.Sum256([]byte(parent + ":" + ts))
	sig, _ := appKey.Sign(digest[:])
	token := hex.EncodeToString(sig.Serialize()) + ":" + ts

	get := func(topic string, withParentToken func(*http.Request) *http.Request) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/data?topic="+topic+"&limit=10", nil)
		req.Host = "localhost"
		req.Header.Set("X-App-Token", token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, withParentToken(req))
		return w
	}
	payloadOf := func(topic string, w *httptest.ResponseRecorder) string {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("GET /data?topic=%s: expected 200, got %d: %s", topic, w.Code, w.Body.String())
		}
		var resp struct {
			Count     int                      `json:"count"`
			Envelopes []map[string]interface{} `json:"envelopes"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Count != 1 || len(resp.Envelopes) != 1 || resp.Envelopes[0]["topic"] != topic {
			t.Fatalf("GET /data?topic=%s must return that topic's one envelope only, got count=%d envelopes=%v", topic, resp.Count, resp.Envelopes)
		}
		payload, _ := resp.Envelopes[0]["payload"].(string)
		return payload
	}
	asSent := func(r *http.Request) *http.Request { return r }

	const redacted = "token-gated content" // the placeholder of a redacted token-model payload
	if payload := payloadOf(parent, get(parent, asSent)); strings.Contains(payload, redacted) || !strings.Contains(payload, `"test"`) {
		t.Fatalf("the parent envelope, on the token's own validated topic, should not be redacted: %s", payload)
	}
	if w := get(child, asSent); w.Code != http.StatusForbidden {
		t.Fatalf("the parent's token on %q: got %d %s, want 403 from the token gate", child, w.Code, w.Body.String())
	}

	// Past the gate, with the context it set for the parent's token.
	srv.tokenGate = nil
	srv.mux = http.NewServeMux()
	srv.routes()
	validatedForParent := func(r *http.Request) *http.Request {
		return r.WithContext(withAppTokenIssuer(withAppTokenTopic(r.Context(), parent), appPubHex))
	}
	if payload := payloadOf(child, get(child, validatedForParent)); !strings.Contains(payload, redacted) {
		t.Fatalf("a token validated for %q, by the key that also gates %q, must not unredact it: %s", parent, child, payload)
	}
}
