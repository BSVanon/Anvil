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

// --- A payer never sees more than an anonymous caller on a
// discovery/metadata route, and private topic metadata never
// leaks through a path that was never `.Private`-gated at all. ---

// payerGet issues a GET with a verified x402 proof for path against a
// charging srv and returns the recorder. t.Fatal on anything but 200.
func payerGet(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	ch := getChallenge(t, srv, "GET", path)
	proofB64 := buildProof(t, ch, 200, testPayeeScript(t))
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("payer GET %s: expected 200, got %d: %s", path, w.Code, w.Body.String())
	}
	return w
}

// TestPayerSeesPublicOnlyDiscovery: a verified payment does not
// widen what GET /topics, GET /topics/{topic}, or GET /identity/{pubkey}
// show — a payer sees exactly the same public-only view an anonymous caller
// does. These routes gate on isAuthed (operator only), never on a payment;
// letting isPaid widen them would let a payer see a private topic's
// name/count/timestamp or a private identity payload.
func TestPayerSeesPublicOnlyDiscovery(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	storePrivate(t, srv, `{"secret":"sealed"}`) // lacriada:household-x
	const pub = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
	storeEnv(t, srv, "identity:"+pub, `{"secret":"private-identity"}`, pub, 100, true)

	if w := payerGet(t, srv, "/topics"); strings.Contains(w.Body.String(), "lacriada:household-x") {
		t.Fatal("a payer must not see a private topic via GET /topics")
	}

	ch2 := getChallenge(t, srv, "GET", "/topics/lacriada:household-x")
	proof2 := buildProof(t, ch2, 200, testPayeeScript(t))
	req2 := httptest.NewRequest("GET", "/topics/lacriada:household-x", nil)
	req2.Host = "localhost"
	req2.Header.Set(HeaderX402Proof, proof2)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("GET /topics/{private}: a payer should get 404 (same as anonymous), got %d: %s", w2.Code, w2.Body.String())
	}

	ch3 := getChallenge(t, srv, "GET", "/identity/"+pub)
	proof3 := buildProof(t, ch3, 200, testPayeeScript(t))
	req3 := httptest.NewRequest("GET", "/identity/"+pub, nil)
	req3.Host = "localhost"
	req3.Header.Set(HeaderX402Proof, proof3)
	w3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("GET /identity/{pubkey}: a payer should get 404 (same as anonymous), got %d: %s", w3.Code, w3.Body.String())
	}
}

// TestTokenGatingDisabledShowsNothingPrivateViaDiscovery: disabling
// token gating (allow_token_gating=false, so srv.tokenGate is nil) creates
// no new leak on the discovery routes — a ?topic= naming a token-model
// topic has no bearing on isAuthed, so a private topic's metadata stays
// hidden regardless of what ?topic= names.
func TestTokenGatingDisabledShowsNothingPrivateViaDiscovery(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"sealed"}`) // lacriada:household-x
	const pub = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
	storeEnv(t, srv, "identity:"+pub, `{"secret":"private-identity"}`, pub, 100, true)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	seedEnvelope(t, srv.envelopeStore, "some:token-topic", &envelope.Monetization{
		Model:      envelope.MonetizationToken,
		AuthPubkey: appPubHex,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, false) // allow_token_gating=false
	if srv.tokenGate != nil {
		t.Fatal("NewTokenGate(resolver, false) should be nil")
	}
	srv.mux = http.NewServeMux()
	srv.routes()

	req1 := httptest.NewRequest("GET", "/topics?topic=some:token-topic", nil)
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)
	if strings.Contains(w1.Body.String(), "lacriada:household-x") {
		t.Fatal("GET /topics must not show the private topic")
	}

	req2 := httptest.NewRequest("GET", "/topics/lacriada:household-x?topic=some:token-topic", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("GET /topics/{private} must still 404, got %d", w2.Code)
	}

	req3 := httptest.NewRequest("GET", "/identity/"+pub+"?topic=some:token-topic", nil)
	w3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("GET /identity/{pubkey} must still 404, got %d", w3.Code)
	}
}

// TestAppTokenDoesNotWidenDiscoveryOrStats: a validated app token (Model 4)
// for a topic has no bearing on isAuthed. GET /topics, GET /topics/{topic},
// GET /identity/{pubkey}, and GET /stats all still show the public-only
// view even when the request's ?topic= names exactly the topic the token
// was validated for, and that same topic also carries a private envelope.
// isAuthed checks only the operator token (auth.go); these routes must
// never start consulting the app-token context instead.
func TestAppTokenDoesNotWidenDiscoveryOrStats(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	const pub = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"

	// "Mixed" topic: a public Model-4 declaration (so a token can validate
	// against it) plus a private envelope — same pattern as
	// TestAppTokenDoesNotUnlockPrivateEnvelope.
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "appgated:discovery-mixed", Payload: `{"tier":"public"}`,
		Pubkey: pub, Signature: "3045022100abcd", TTL: 60, Timestamp: 1700000000,
		Monetization: &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex},
	})
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "appgated:discovery-mixed", Payload: `{"secret":"discovery-must-not-see-this"}`,
		Pubkey: pub, Signature: "3045022100abcd", TTL: 60, Timestamp: 1700000001,
		Private: true,
	})

	// Same mixed pattern on an identity: topic, so GET /identity/{pubkey}
	// has a private envelope to hide too.
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "identity:" + pub, Payload: `{"tier":"public"}`,
		Pubkey: pub, Signature: "3045022100abcd", TTL: 60, Timestamp: 1700000000,
		Monetization: &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex},
	})
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: "identity:" + pub, Payload: `{"secret":"identity-must-not-see-this"}`,
		Pubkey: pub, Signature: "3045022100abcd", TTL: 60, Timestamp: 1700000001,
		Private: true,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	mintToken := func(topic string) string {
		ts := fmt.Sprintf("%d", time.Now().Unix())
		digest := sha256.Sum256([]byte(topic + ":" + ts))
		sig, _ := appKey.Sign(digest[:])
		return hex.EncodeToString(sig.Serialize()) + ":" + ts
	}

	req1 := httptest.NewRequest("GET", "/topics?topic=appgated:discovery-mixed", nil)
	req1.Header.Set("X-App-Token", mintToken("appgated:discovery-mixed"))
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("GET /topics: expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	if strings.Contains(w1.Body.String(), "discovery-must-not-see-this") {
		t.Fatalf("GET /topics must not widen with a validated app token: %s", w1.Body.String())
	}

	req2 := httptest.NewRequest("GET", "/topics/appgated:discovery-mixed?topic=appgated:discovery-mixed", nil)
	req2.Header.Set("X-App-Token", mintToken("appgated:discovery-mixed"))
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("GET /topics/{topic}: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var topicResp struct {
		Topic struct {
			Count int `json:"count"`
		} `json:"topic"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &topicResp); err != nil {
		t.Fatalf("GET /topics/{topic}: invalid JSON: %v", err)
	}
	if topicResp.Topic.Count != 1 {
		t.Fatalf("GET /topics/{topic}: expected count=1 (public envelope only), got %d — a validated app token must not widen the aggregate", topicResp.Topic.Count)
	}

	req3 := httptest.NewRequest("GET", "/identity/"+pub+"?topic=identity:"+pub, nil)
	req3.Header.Set("X-App-Token", mintToken("identity:"+pub))
	w3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("GET /identity/{pubkey}: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
	if strings.Contains(w3.Body.String(), "identity-must-not-see-this") {
		t.Fatalf("GET /identity/{pubkey} must not widen with a validated app token: %s", w3.Body.String())
	}

	req4 := httptest.NewRequest("GET", "/stats?topic=appgated:discovery-mixed", nil)
	req4.Header.Set("X-App-Token", mintToken("appgated:discovery-mixed"))
	w4 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("GET /stats: expected 200, got %d: %s", w4.Code, w4.Body.String())
	}
	if strings.Contains(w4.Body.String(), "discovery-must-not-see-this") {
		t.Fatalf("GET /stats must not widen with a validated app token: %s", w4.Body.String())
	}
}
