package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// storePrivate stores a private (read-gated) envelope directly for testing.
func storePrivate(t *testing.T, srv *Server, payloadSecret string) {
	t.Helper()
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type:      "data",
		Topic:     "lacriada:household-x",
		Payload:   payloadSecret,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd",
		TTL:       60,
		Timestamp: 1700000000,
		Private:   true,
	})
}

func queryPrivateTopic(t *testing.T, srv *Server, setAuth func(*http.Request)) []map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("GET", "/data?topic=lacriada:household-x&limit=10", nil)
	if setAuth != nil {
		setAuth(req)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Count     int                      `json:"count"`
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != len(resp.Envelopes) {
		t.Fatalf("count %d != len(envelopes) %d — count must not leak omitted private envelopes", resp.Count, len(resp.Envelopes))
	}
	return resp.Envelopes
}

// TestPrivateEnvelopeOmittedForPublicReads: an unauthenticated GET /data must
// not see a private envelope AT ALL — neither the sealed blob nor its metadata
// (topic/pubkey/timestamp). This is the (2)+(3) guarantee.
func TestPrivateEnvelopeOmittedForPublicReads(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`)

	envs := queryPrivateTopic(t, srv, nil) // no auth
	if len(envs) != 0 {
		t.Fatalf("private envelope must be omitted entirely for public reads; got %d: %v", len(envs), envs)
	}
}

// TestPrivateEnvelopeVisibleForBearerAuth: the operator bearer token sees it in
// full (this is how LaCriada's coordinator reads the mirror on failover).
func TestPrivateEnvelopeVisibleForBearerAuth(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"visible-to-operator"}`)

	envs := queryPrivateTopic(t, srv, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer test-token")
	})
	if len(envs) != 1 {
		t.Fatalf("authenticated read should see the private envelope; got %d", len(envs))
	}
	if p, _ := envs[0]["payload"].(string); !strings.Contains(p, "visible-to-operator") {
		t.Fatalf("authenticated read should see full payload, got: %v", envs[0]["payload"])
	}
}

// TestPrivateSpoofedAnvilAuthedRejected: a client cannot bypass the read-gate
// by sending X-Anvil-Authed itself. That header is an internal signal stripped
// at the trust boundary (Handler), so a spoofed value leaves the private
// envelope omitted — this is what makes the gate safe on an ungated public node
// (a node with a real token/payment gate re-sets the header server-side on
// genuine success, covered by the middleware's own tests).
func TestPrivateSpoofedAnvilAuthedRejected(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"do-not-leak"}`)

	envs := queryPrivateTopic(t, srv, func(r *http.Request) {
		r.Header.Set("X-Anvil-Authed", "true") // spoof attempt — must be stripped
	})
	if len(envs) != 0 {
		t.Fatalf("spoofed X-Anvil-Authed must NOT authorize a private read; got %d", len(envs))
	}
}

func storePublicTopic(t *testing.T, srv *Server, topic string) {
	t.Helper()
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type:      "data",
		Topic:     topic,
		Payload:   `{"x":1}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd",
		TTL:       60,
		Timestamp: 1700000000,
	})
}

// TestPrivateTopicHiddenFromDiscoveryList: GET /topics must not surface a
// private topic's name/count/timestamp to unauthenticated callers, but must to
// authenticated ones. (Codex 1b290a5d HIGH — the discovery leak.)
func TestPrivateTopicHiddenFromDiscoveryList(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"sealed"}`) // lacriada:household-x (private)
	storePublicTopic(t, srv, "oracle:rates:bsv")

	req := httptest.NewRequest("GET", "/topics", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "lacriada:household-x") {
		t.Fatal("private topic must be hidden from unauthenticated /topics")
	}
	if !strings.Contains(w.Body.String(), "oracle:rates:bsv") {
		t.Fatal("public topic should still be listed")
	}

	req2 := httptest.NewRequest("GET", "/topics", nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if !strings.Contains(w2.Body.String(), "lacriada:household-x") {
		t.Fatal("authenticated /topics should list the private topic")
	}
}

// TestGetPrivateTopicGatedFromDiscovery: GET /topics/{private} returns 404 to
// unauthenticated callers (existence + publisher hidden), 200 to authed.
func TestGetPrivateTopicGatedFromDiscovery(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"sealed"}`)

	req := httptest.NewRequest("GET", "/topics/lacriada:household-x", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unauthenticated GET of a private topic should 404, got %d (body=%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "0231600bb") {
		t.Fatal("private topic publisher pubkey must not leak")
	}

	req2 := httptest.NewRequest("GET", "/topics/lacriada:household-x", nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("authenticated GET of a private topic should 200, got %d", w2.Code)
	}
}

func storeEnv(t *testing.T, srv *Server, topic, payload, pubkey string, ts int64, private bool) {
	t.Helper()
	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: topic, Payload: payload, Pubkey: pubkey,
		Signature: "3045022100abcd", TTL: 60, Timestamp: ts, Private: private,
	})
}

// TestMixedTopicHidesPrivateHistoryFromDiscovery: a topic whose LATEST envelope
// is public but which also has older PRIVATE envelopes must, for unauthenticated
// callers, report only the public count/timestamp/publisher (private history
// invisible); authenticated callers see the full aggregate. (Codex 95ca1f2e
// round-2 HIGH — the mixed-topic discovery leak.)
func TestMixedTopicHidesPrivateHistoryFromDiscovery(t *testing.T) {
	srv := testServer(t)
	const (
		privPub = "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		pubPub  = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
	)
	topic := "mixed:topic"
	storeEnv(t, srv, topic, "priv1", privPub, 100, true)
	storeEnv(t, srv, topic, "priv2", privPub, 101, true)
	storeEnv(t, srv, topic, "priv3", privPub, 102, true)
	storeEnv(t, srv, topic, "pub1", pubPub, 200, false)
	storeEnv(t, srv, topic, "pub2", pubPub, 201, false) // latest, public

	// Unauthenticated GET /topics/{topic}: public-only view.
	req := httptest.NewRequest("GET", "/topics/mixed:topic", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Topic struct {
			Count       int    `json:"count"`
			LastUpdated int64  `json:"last_updated"`
			Publisher   string `json:"publisher"`
		} `json:"topic"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Topic.Count != 2 {
		t.Fatalf("unauthed count must exclude private history: want 2, got %d", resp.Topic.Count)
	}
	if resp.Topic.LastUpdated != 201 {
		t.Fatalf("unauthed last_updated must be the public latest (201), got %d", resp.Topic.LastUpdated)
	}
	if resp.Topic.Publisher != pubPub {
		t.Fatalf("unauthed publisher must be the public one, got %q", resp.Topic.Publisher)
	}

	// Authenticated: full aggregate.
	req2 := httptest.NewRequest("GET", "/topics/mixed:topic", nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	var resp2 struct {
		Topic struct {
			Count int `json:"count"`
		} `json:"topic"`
	}
	json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2.Topic.Count != 5 {
		t.Fatalf("authed count should be the full aggregate 5, got %d", resp2.Topic.Count)
	}

	// Unauthenticated /topics list: mixed topic present with public count only.
	req3 := httptest.NewRequest("GET", "/topics", nil)
	w3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w3, req3)
	if !strings.Contains(w3.Body.String(), "mixed:topic") {
		t.Fatal("mixed topic (has public envelopes) should appear in unauthenticated /topics")
	}
}

// TestPrivateMetaNotLeakedViaDiscovery: a private meta:<topic> envelope must not
// leak through /topics/{topic} enrichment to unauthenticated callers, but must
// to authenticated ones. (Codex 3b214aa2 round-3 HIGH — helper-read leak.)
func TestPrivateMetaNotLeakedViaDiscovery(t *testing.T) {
	srv := testServer(t)
	const pub = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
	storeEnv(t, srv, "shop:widgets", "pub-data", pub, 100, false)                      // public data topic
	storeEnv(t, srv, "meta:shop:widgets", `{"secret":"private-meta-leak"}`, pub, 101, true) // private meta

	req := httptest.NewRequest("GET", "/topics/shop:widgets", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-meta-leak") {
		t.Fatal("private meta: payload leaked via unauthenticated discovery")
	}

	req2 := httptest.NewRequest("GET", "/topics/shop:widgets", nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if !strings.Contains(w2.Body.String(), "private-meta-leak") {
		t.Fatal("authenticated discovery should include the (private) meta payload")
	}
}

// TestPrivateIdentityNotLeakedViaGetIdentity: GET /identity/{pubkey} must not
// return a private identity envelope to unauthenticated callers (404), but must
// to authenticated ones. (Codex 3b214aa2 round-3 HIGH — /identity had no gate.)
func TestPrivateIdentityNotLeakedViaGetIdentity(t *testing.T) {
	srv := testServer(t)
	const pub = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
	storeEnv(t, srv, "identity:"+pub, `{"secret":"private-identity-leak"}`, pub, 100, true)

	req := httptest.NewRequest("GET", "/identity/"+pub, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("private identity must 404 for unauthenticated caller, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "private-identity-leak") {
		t.Fatal("private identity payload leaked via GET /identity")
	}

	req2 := httptest.NewRequest("GET", "/identity/"+pub, nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("authenticated GET /identity should 200, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "private-identity-leak") {
		t.Fatal("authenticated GET /identity should return the identity payload")
	}
}

// TestPrivatePublisherIdentityOmittedFromTopicGet: GET /topics/{topic} must not
// surface a publisher's PRIVATE identity envelope via the publisher_identity
// field to unauthenticated callers, but must to authenticated ones. (Codex
// cc800b5c round-4 belt-and-suspenders for the publisher_identity path.)
func TestPrivatePublisherIdentityOmittedFromTopicGet(t *testing.T) {
	srv := testServer(t)
	const pub = "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"
	storeEnv(t, srv, "shop:widgets", "pub-data", pub, 100, false)                            // public data topic, publisher=pub
	storeEnv(t, srv, "identity:"+pub, `{"secret":"private-identity-leak"}`, pub, 101, true) // publisher's PRIVATE identity

	req := httptest.NewRequest("GET", "/topics/shop:widgets", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private-identity-leak") {
		t.Fatal("private publisher identity leaked via /topics/{topic} for unauthenticated caller")
	}
	if strings.Contains(w.Body.String(), "publisher_identity") {
		t.Fatal("publisher_identity should be absent when the identity is private + caller unauthenticated")
	}

	req2 := httptest.NewRequest("GET", "/topics/shop:widgets", nil)
	req2.Header.Set("Authorization", "Bearer test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if !strings.Contains(w2.Body.String(), "private-identity-leak") {
		t.Fatal("authenticated /topics/{topic} should include the (private) publisher identity")
	}
}
