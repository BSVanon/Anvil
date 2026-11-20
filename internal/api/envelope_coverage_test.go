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

// Each envelope's payload is unlocked by its own monetization rule
// (envelopeForRequest, envelope_redaction.go), never by the request having
// paid at all: a payment unlocks a priced envelope only when one of its
// outputs pays that envelope's own payee its own (capped) price, it never
// unlocks a token-model envelope, and an app token unlocks only token-model
// envelopes that name the key that issued it.

// otherAppScript is a third P2PKH script, neither the node's nor
// appPayeeScript's.
func otherAppScript() string { return "76a914cccccccccccccccccccccccccccccccccccccccc88ac" }

// seedEnvelopeAt stores a durable envelope on topic with payload, signed by a
// fresh key, at unix time ts.
func seedEnvelopeAt(t *testing.T, es *envelope.Store, topic, payload string, ts int64, mon *envelope.Monetization) {
	t.Helper()
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{Type: "data", Topic: topic, Payload: payload, Durable: true, Timestamp: ts, Monetization: mon}
	env.Sign(key)
	if err := es.Ingest(env); err != nil {
		t.Fatalf("seed %s: %v", topic, err)
	}
}

// payloadsByMarker returns, for each marker, whether some envelope in envs
// shows it in its payload, that is unredacted.
func payloadsByMarker(envs []map[string]interface{}, markers ...string) map[string]bool {
	seen := make(map[string]bool, len(markers))
	for _, e := range envs {
		p, _ := e["payload"].(string)
		for _, m := range markers {
			if strings.Contains(p, m) {
				seen[m] = true
			}
		}
	}
	return seen
}

func tokenModel(key *ec.PrivateKey) *envelope.Monetization {
	return &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: hex.EncodeToString(key.PubKey().Compressed())}
}

func passthrough(payee string, price int) *envelope.Monetization {
	return &envelope.Monetization{Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: payee, PriceSats: price}
}

// payAndQuery pays path's challenge with paySats to the challenge's own payee
// and returns the /data envelopes.
func payAndQuery(t *testing.T, srv *Server, path string, paySats uint64) (*X402Challenge, []map[string]interface{}) {
	t.Helper()
	ch := getChallenge(t, srv, http.MethodGet, path)
	_, envs := queryWithProof(t, srv, path, ch, buildProof(t, ch, paySats, ch.PayeeLockingScriptHex))
	return ch, envs
}

// A same-topic envelope asking 1 sat to another payee must not let a 1-sat
// payment unlock an older envelope priced 1000 to its own payee.
func TestPaymentToCheapNewerEnvelopeLeavesPricierEnvelopeRedacted(t *testing.T) {
	srv := testServer(t)
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "prem", `{"secret":"honest-1000"}`, base, passthrough(appPayeeScript(), 1000))
	seedEnvelopeAt(t, srv.envelopeStore, "prem", `{"x":"cheap-1"}`, base+100, passthrough(otherAppScript(), 1))
	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	ch, envs := payAndQuery(t, srv, "/data?topic=prem", 1)
	if ch.AmountSats != 1 || ch.PayeeLockingScriptHex != otherAppScript() {
		t.Fatalf("the challenge should ask the newest envelope's 1 sat, got %d to %s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}
	seen := payloadsByMarker(envs, "honest-1000", "cheap-1")
	if seen["honest-1000"] {
		t.Fatal("1 sat paid to another payee unlocked the envelope priced 1000 to its own payee")
	}
	if !seen["cheap-1"] {
		t.Fatal("the envelope the payment did pay must be unlocked")
	}
}

// The same rule over SSE: the honest envelope priced 1000 arrives on the
// stream redacted for a subscriber who paid another payee 1 sat.
func TestSubscribePaymentToCheapNewerEnvelopeLeavesPricierRedacted(t *testing.T) {
	srv := testServer(t)
	seedEnvelopeAt(t, srv.envelopeStore, "sprem", `{"x":"cheap-1"}`, time.Now().Unix()+100, passthrough(otherAppScript(), 1))
	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	path := "/data/subscribe?topic=sprem"
	ch := getChallenge(t, srv, http.MethodGet, path)
	proof := buildProof(t, ch, uint64(ch.AmountSats), ch.PayeeLockingScriptHex)
	resp, cancel := subscribeSSE(t, ts, path, "localhost", func(r *http.Request) { r.Header.Set(HeaderX402Proof, proof) })
	defer cancel()
	defer resp.Body.Close()
	waitForSSESubscription(t, srv, "sprem")

	key, _ := ec.NewPrivateKey()
	honest := &envelope.Envelope{Type: "data", Topic: "sprem", Payload: `{"secret":"sse-honest-1000"}`, Timestamp: time.Now().Unix(),
		Monetization: passthrough(appPayeeScript(), 1000)}
	honest.Sign(key)
	srv.NotifyEnvelope(honest)
	body := readSSEUntilSentinel(t, srv, resp, "sprem")
	if strings.Contains(body, "sse-honest-1000") {
		t.Fatal("1 sat paid to another payee streamed the envelope priced 1000 to its own payee unredacted")
	}
	if !strings.Contains(body, "paid content") {
		t.Fatalf("the honest envelope should arrive redacted; got:\n%s", body)
	}
}

// The node's toll covers what the node prices, unmonetized content, and never
// an envelope priced to an app's payee: not when the toll is below the app's
// price, and not when it is above it, since it pays the node's script.
func TestNodeTollLeavesAppPricedEnvelopeRedacted(t *testing.T) {
	for _, tc := range []struct{ toll, appPrice int }{{100, 1000}, {1000, 100}} {
		srv := testServer(t)
		base := time.Now().Unix()
		seedEnvelopeAt(t, srv.envelopeStore, "a", `{"secret":"app-priced"}`, base, passthrough(appPayeeScript(), tc.appPrice))
		seedEnvelopeAt(t, srv.envelopeStore, "a", `{"free":"node-priced"}`, base+100, nil)
		srv.paymentGate = NewPaymentGate(PaymentGateConfig{ // passthrough off: only the node's toll is charged
			PriceSats: tc.toll, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
			Resolver: NewTopicMonetizationResolver(srv.envelopeStore),
		})
		srv.mux = http.NewServeMux()
		srv.routes()

		ch, envs := payAndQuery(t, srv, "/data?topic=a", uint64(tc.toll))
		if ch.AmountSats != tc.toll || ch.PayeeLockingScriptHex != testPayeeScript(t) {
			t.Fatalf("toll %d: the challenge should be the node's toll, got %d to %s", tc.toll, ch.AmountSats, ch.PayeeLockingScriptHex)
		}
		seen := payloadsByMarker(envs, "app-priced", "node-priced")
		if seen["app-priced"] {
			t.Fatalf("a %d-sat node toll unlocked an envelope priced %d to an app payee", tc.toll, tc.appPrice)
		}
		if !seen["node-priced"] {
			t.Fatalf("toll %d: the unmonetized envelope must be served", tc.toll)
		}
	}
}

// With token gating off, the node's toll still never unlocks a token-model
// envelope, whose app sells credentials and has no payee.
func TestNodeTollLeavesTokenModelEnvelopeRedacted(t *testing.T) {
	srv := testServer(t)
	key, _ := ec.NewPrivateKey()
	seedEnvelopeAt(t, srv.envelopeStore, "lic", `{"secret":"licensed-only"}`, time.Now().Unix(), tokenModel(key))
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
		Resolver: NewTopicMonetizationResolver(srv.envelopeStore),
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	_, envs := payAndQuery(t, srv, "/data?topic=lic", 100)
	if payloadsByMarker(envs, "licensed-only")["licensed-only"] {
		t.Fatal("a 100-sat node toll unlocked a token-model payload")
	}
}

// A payment never unlocks a token-model envelope, even one that also names a
// payee and a price the payment pays.
func TestPaymentNeverUnlocksTokenModelEnvelope(t *testing.T) {
	srv := testServer(t)
	key, _ := ec.NewPrivateKey()
	base := time.Now().Unix()
	tok := tokenModel(key)
	tok.PayeeLockingScriptHex, tok.PriceSats = appPayeeScript(), 50
	seedEnvelopeAt(t, srv.envelopeStore, "mixed", `{"secret":"token-only"}`, base, tok)
	seedEnvelopeAt(t, srv.envelopeStore, "mixed", `{"x":"paid-50"}`, base+100, passthrough(appPayeeScript(), 50))
	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	_, envs := payAndQuery(t, srv, "/data?topic=mixed", 50)
	seen := payloadsByMarker(envs, "token-only", "paid-50")
	if seen["token-only"] {
		t.Fatal("a payment unlocked a token-model envelope")
	}
	if !seen["paid-50"] {
		t.Fatal("the passthrough envelope the payment paid must be unlocked")
	}
}

// An envelope priced above max_app_price_sats costs the capped price, the
// price its 402 challenge asks for: paying that unlocks it, and paying less
// does not.
func TestCappedAppPriceUnlocksAtTheCapOnly(t *testing.T) {
	newSrv := func() *Server {
		srv := testServer(t)
		srv.paymentGate = NewPaymentGate(PaymentGateConfig{
			NonceProvider: &DevNonceProvider{}, Resolver: NewTopicMonetizationResolver(srv.envelopeStore),
			AllowPassthrough: true, MaxAppPriceSats: 500,
		})
		srv.mux = http.NewServeMux()
		srv.routes()
		return srv
	}
	base := time.Now().Unix()

	srv := newSrv()
	seedEnvelopeAt(t, srv.envelopeStore, "capped", `{"secret":"declared-1000"}`, base, passthrough(appPayeeScript(), 1000))
	ch, envs := payAndQuery(t, srv, "/data?topic=capped", 500)
	if ch.AmountSats != 500 {
		t.Fatalf("the challenge should ask the capped 500 sats, got %d", ch.AmountSats)
	}
	if !payloadsByMarker(envs, "declared-1000")["declared-1000"] {
		t.Fatal("paying the capped price must unlock the envelope")
	}

	// A newer envelope asks 300 to the same payee; paying 300 covers it, and
	// not the older one, whose capped price is 500.
	srv = newSrv()
	seedEnvelopeAt(t, srv.envelopeStore, "capped", `{"secret":"declared-1000"}`, base, passthrough(appPayeeScript(), 1000))
	seedEnvelopeAt(t, srv.envelopeStore, "capped", `{"x":"asks-300"}`, base+100, passthrough(appPayeeScript(), 300))
	_, envs = payAndQuery(t, srv, "/data?topic=capped", 300)
	seen := payloadsByMarker(envs, "declared-1000", "asks-300")
	if seen["declared-1000"] {
		t.Fatal("paying 300, less than the capped 500, must not unlock the envelope")
	}
	if !seen["asks-300"] {
		t.Fatal("the envelope asking 300 must be unlocked by 300")
	}
}

// queryWithAppToken GETs path with the X-App-Token token.
func queryWithAppToken(t *testing.T, srv *Server, path, token string) (int, []map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "localhost"
	req.Header.Set("X-App-Token", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var resp struct {
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	return w.Code, resp.Envelopes
}

// A newer token-model envelope on the same topic, naming the attacker's own
// key, lets the attacker's self-issued token through the token gate, but it
// unlocks only the attacker's own envelope: never an older token-model
// envelope that names another issuer, nor an older envelope priced to its own
// payee. The remaining effect is a denial of service: the newest rule now
// names the attacker's key, so honest token holders and payers are turned
// away. Closing that needs topic ownership, which is a known limit.
func TestSelfIssuedTokenCannotUnlockHonestEnvelopeOnSameTopic(t *testing.T) {
	honestKey, _ := ec.NewPrivateKey()
	attackerKey, _ := ec.NewPrivateKey()
	for _, honest := range []*envelope.Monetization{tokenModel(honestKey), passthrough(appPayeeScript(), 1000)} {
		srv := testServer(t)
		base := time.Now().Unix()
		seedEnvelopeAt(t, srv.envelopeStore, "prem", `{"secret":"honest"}`, base, honest)
		seedEnvelopeAt(t, srv.envelopeStore, "prem", `{"x":"attacker-own"}`, base+100, tokenModel(attackerKey))
		resolver := NewTopicMonetizationResolver(srv.envelopeStore)
		srv.tokenGate = NewTokenGate(resolver, true)
		srv.paymentGate = testGateWithAppPayments(t, 0, srv.envelopeStore)
		srv.mux = http.NewServeMux()
		srv.routes()

		code, envs := queryWithAppToken(t, srv, "/data?topic=prem", mintAppToken(attackerKey, "prem"))
		if code != http.StatusOK {
			t.Fatalf("%s: the attacker's token on its own newest rule: got %d, want 200", honest.Model, code)
		}
		seen := payloadsByMarker(envs, "honest", "attacker-own")
		if seen["honest"] {
			t.Fatalf("%s: the attacker's self-issued token unlocked the honest envelope", honest.Model)
		}
		if !seen["attacker-own"] {
			t.Fatalf("%s: the attacker's token should unlock the envelope naming its own key", honest.Model)
		}
	}
}
