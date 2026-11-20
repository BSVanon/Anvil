package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// --- Item 6 / cold review RISK 4: a toll paid against one topic must not
// unredact a different topic's own, separately-priced payload, even when
// envelope/store.go's prefix-scanned listing (documented for listing,
// docs/ANVIL_CAPABILITIES.md:77) happens to return both in the same
// response. An honest payment for a topic's OWN price must still unlock
// that topic's own content. ---

func TestCheapTollDoesNotUnlockSiblingTopicPremiumPayload(t *testing.T) {
	srv := testServer(t)
	// "a" is cheap, priced to the node's own test payee.
	seedEnvelope(t, srv.envelopeStore, "a", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: testPayeeScript(t), PriceSats: 1,
	})
	// "a:premium" is expensive, priced to a different app payee — only the
	// durable prefix scan (topic "a" matches keys "d:a:...") ever puts it in
	// the same /data?topic=a response as "a" itself.
	seedEnvelope(t, srv.envelopeStore, "a:premium", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 1000,
	})

	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore) // node itself is free
	srv.mux = http.NewServeMux()
	srv.routes()

	path := "/data?topic=a&limit=10"
	ch := getChallenge(t, srv, "GET", path)
	if ch.AmountSats != 1 {
		t.Fatalf("expected topic a's own 1-sat passthrough price, got %d", ch.AmountSats)
	}
	proofB64 := buildProof(t, ch, 1, testPayeeScript(t))
	_, envs := queryWithProof(t, srv, path, ch, proofB64)

	var sawA, sawPremium bool
	var aPayload, premiumPayload string
	for _, e := range envs {
		switch e["topic"] {
		case "a":
			sawA = true
			aPayload, _ = e["payload"].(string)
		case "a:premium":
			sawPremium = true
			premiumPayload, _ = e["payload"].(string)
		}
	}
	if !sawA || !sawPremium {
		t.Fatalf("expected both 'a' and 'a:premium' in the prefix-scanned listing for topic=a, got envelopes: %v", envs)
	}
	if strings.Contains(aPayload, "paid content") {
		t.Fatalf("an honest payment for topic a's own 1-sat price must unlock a's own payload, got: %s", aPayload)
	}
	if !strings.Contains(premiumPayload, "paid content") {
		t.Fatalf("a 1-sat toll paid against topic 'a' must not unlock a:premium's own 1000-sat payload, got: %s", premiumPayload)
	}
}

// --- Item 8 / cold review BL2(a): a self-issued app token (or a
// self-created topic's own declared pricing) must never waive the node's
// toll on a node route — only GET /data and GET /data/subscribe are content
// routes (isAppContentRoute, content_route.go). ---

func TestAppTokenNeverWaivesNodeTollOnNodeRoute(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	seedEnvelope(t, srv.envelopeStore, "evil:t", &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats: 50, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}, Resolver: resolver,
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/stats?topic=evil:t", nil)
	req.Host = "localhost"
	req.Header.Set("X-App-Token", mintAppToken(appKey, "evil:t"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("a self-issued app token for an attacker-named topic must never waive the node's toll on a node route (/stats); got %d: %s", w.Code, w.Body.String())
	}
}

// TestAppTokenNeverBlocksNodeRoute is BL2(a)'s other half: a token-gated
// topic must also never collaterally 401/403 a node route just because the
// query string happens to name it — a legitimate caller with no token at
// all must still reach /stats normally (node is free here).
func TestAppTokenNeverBlocksNodeRoute(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	seedEnvelope(t, srv.envelopeStore, "evil:t", &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/stats?topic=evil:t", nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("a token-gated topic must never 401/403 a node route that merely echoes ?topic=; got %d: %s", w.Code, w.Body.String())
	}
}

// --- Item 8 / cold review BL2(b): a newer sub-topic envelope must not
// hijack the parent topic's own pricing or token-gating. Resolve
// (payment_resolve.go) now skips any envelope whose own Topic isn't an
// exact match. ---

func TestSubtopicEnvelopeDoesNotHijackParentTopicResolution(t *testing.T) {
	srv := testServer(t)

	// QueryByTopic (envelope/store.go) returns every durable envelope
	// whose own Topic matches the prefix scan, newest-first by timestamp —
	// so the realistic hijack is the attacker's sub-topic envelope landing
	// at a LATER timestamp than the legitimate topic's own, which is what
	// made it surface first before Resolve's exact-match fix. seedEnvelope
	// (noncustodial_test.go) stamps time.Now() implicitly, which is only
	// second-resolution and ties for two calls microseconds apart — too
	// close to reliably exercise that ordering, so both envelopes are
	// seeded here directly with explicit, clearly-ordered timestamps.
	seedEnvelopeAt := func(topic string, mon *envelope.Monetization, ts int64) {
		t.Helper()
		key, _ := ec.NewPrivateKey()
		env := &envelope.Envelope{
			Type: "data", Topic: topic, Payload: `{"test": true}`, Durable: true, Timestamp: ts, Monetization: mon,
		}
		env.Sign(key)
		if err := srv.envelopeStore.Ingest(env); err != nil {
			t.Fatalf("seed envelope at %d: %v", ts, err)
		}
	}

	base := time.Now().Unix()
	// "prem" has its own honest passthrough price, published first.
	seedEnvelopeAt("prem", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 1000,
	}, base)
	// An attacker's newer sub-topic envelope, token-gated to their own key,
	// published strictly later.
	attackerKey, _ := ec.NewPrivateKey()
	seedEnvelopeAt("prem:x", &envelope.Monetization{
		Model: envelope.MonetizationToken, AuthPubkey: hex.EncodeToString(attackerKey.PubKey().Compressed()),
	}, base+100)

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	mon := resolver.Resolve("prem")
	if mon == nil || mon.Model != envelope.MonetizationPassthrough || mon.PriceSats != 1000 {
		t.Fatalf("expected prem's own passthrough monetization (1000 sats), got %+v", mon)
	}

	// The hijack attempt must not leave an honest payer unable to pay
	// prem's own price and read it: the challenge issued for topic=prem
	// must be prem's own 1000-sat passthrough price to the app's own payee,
	// never prem:x's token requirement or no challenge at all.
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	ch := getChallenge(t, srv, "GET", "/data?topic=prem")
	if ch.AmountSats != 1000 || ch.PayeeLockingScriptHex != appPayeeScript() {
		t.Fatalf("expected prem's own 1000-sat challenge to the app payee, got amount=%d payee=%s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}
}

// --- Item 8 / cold review RISK 3: passthrough self-pricing on a topic must
// never replace the node's own toll on a write. ---

func TestPassthroughNeverReplacesNodeTollOnWrite(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "evil:pt", &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 1,
	})

	srv.paymentGate = testGateWithAppPayments(t, 500, srv.envelopeStore) // node charges 500 for everything
	srv.mux = http.NewServeMux()
	srv.routes()

	ch := getChallenge(t, srv, "POST", "/broadcast?topic=evil:pt")
	if ch.AmountSats != 500 || ch.PayeeLockingScriptHex != testPayeeScript(t) {
		t.Fatalf("a write's toll must always be the node's own price to the node's own payee, never a topic's declared app price; got amount=%d payee=%s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}
}

// --- Item 8 / cold review RISK 4 (via content route, parent-topic query):
// a token-gated sub-topic's payload must stay redacted when it surfaces
// through a query on its parent topic, for a caller with no token at all. ---

func TestTokenGatedSubtopicStaysRedactedViaParentTopicQuery(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	seedEnvelope(t, srv.envelopeStore, "P:tok", &envelope.Monetization{
		Model: envelope.MonetizationToken, AuthPubkey: hex.EncodeToString(appKey.PubKey().Compressed()),
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/data?topic=P&limit=10", nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("querying parent topic P (itself unmonetized) should succeed with no token required; got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /data response: %v", err)
	}
	found := false
	for _, e := range resp.Envelopes {
		if e["topic"] != "P:tok" {
			continue
		}
		found = true
		payload, _ := e["payload"].(string)
		if !strings.Contains(payload, "token-gated content") {
			t.Fatalf("P:tok must be redacted with the token-gated placeholder when surfaced via a query on parent topic P with no X-App-Token; got payload: %s", payload)
		}
	}
	if !found {
		t.Fatal("expected P:tok to be returned by the prefix-scanned listing for topic=P")
	}
}

// TestDataQueryAppTokenMismatchedTopicStaysRedacted is cold review's RISK 5
// for the GET /data path — handlers.go's sibling of
// TestSubscribeAppTokenMismatchedTopicStaysRedacted (sse_app_token_exact_test.go).
// Both redaction loops share the identical condition
// (!paid && !appTokenTopicMatches(r, env.Topic) && mustRedactEnvelope(env)),
// so both call sites need their own regression coverage: a mutation
// specific to handlers.go's copy (e.g. weakening the check to "is any app
// token present on this connection" instead of "is it valid for THIS
// envelope's own topic") would not be caught by
// TestTokenGatedTopicAcceptsValidCredential (noncustodial_test.go) or
// TestTokenGatedSubtopicStaysRedactedViaParentTopicQuery above, since
// neither ever presents a validated token whose topic differs from the
// envelope being evaluated. As with the SSE case, TokenGate.Middleware can
// never hand handlers.go such a mismatched context itself (verifyToken
// binds the signature to the topic it is checked against), so creating it
// directly is the only way to exercise this call site's own exact-match
// requirement.
func TestDataQueryAppTokenMismatchedTopicStaysRedacted(t *testing.T) {
	srv := testServer(t) // no tokenGate configured — nothing but the redaction check itself can gate this

	const topic = "data:risk5-exact-match"
	key, _ := ec.NewPrivateKey()
	seedEnvelope(t, srv.envelopeStore, topic, &envelope.Monetization{
		Model: envelope.MonetizationToken, AuthPubkey: hex.EncodeToString(key.PubKey().Compressed()),
	})

	req := httptest.NewRequest("GET", "/data?topic="+topic, nil)
	req.Host = "localhost"
	// Simulate a validated app token for a DIFFERENT topic than the one
	// being queried — unreachable through the real TokenGate.Middleware
	// (see doc comment above).
	req = req.WithContext(withAppTokenTopic(req.Context(), "data:risk5-other-topic"))

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /data response: %v", err)
	}
	found := false
	for _, e := range resp.Envelopes {
		if e["topic"] != topic {
			continue
		}
		found = true
		payload, _ := e["payload"].(string)
		if !strings.Contains(payload, "token-gated content") {
			t.Fatalf("an app-token context validated for a different topic must not unlock this topic's own token-gated payload; got payload: %s", payload)
		}
	}
	if !found {
		t.Fatalf("expected %s to be returned by the query", topic)
	}
}
