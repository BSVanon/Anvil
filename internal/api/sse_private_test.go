package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// --- GET /data/subscribe (SSE) follows the same authenticated/
// paid split as GET /data, with a real test — an earlier version of this
// test asserted neither the 200 nor that the public envelope actually
// arrived, so it also passed if nothing streamed at all. See
// handleSubscribe, sse.go.
//
// These use a real httptest server (not httptest.NewRecorder) — a
// ResponseRecorder's bytes.Buffer is not safe for the handler goroutine to
// write while the test goroutine reads, which -race catches. A real
// loopback connection is properly synchronized. This mirrors the existing
// pattern in sse_messages_test.go (runSubscribeForReconnectLine).

// waitForSSESubscription polls (short bounded interval, never a single fixed
// sleep standing in for readiness) until the SSE hub has registered a
// subscriber on topic. The subscribe handler registers asynchronously
// relative to the client observing a 200, so sending a notification before
// this returns would race the subscription itself, not just the assertion.
func waitForSSESubscription(t *testing.T, srv *Server, topic string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.sseHub.mu.RLock()
		n := len(srv.sseHub.subs[topic])
		srv.sseHub.mu.RUnlock()
		if n > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for an SSE subscriber on topic %q", topic)
}

// readSSEUntilContains blocks reading resp's body until the accumulated
// bytes contain marker, or the request's context ends and Read returns an
// error — whichever comes first. Used both to wait for an expected event
// (returns fast) and to confirm an absence (returns once the context's
// timeout closes the connection, having read everything that arrived).
func readSSEUntilContains(resp *http.Response, marker string) string {
	buf := make([]byte, 4096)
	var acc []byte
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			acc = append(acc, buf[:n]...)
			if strings.Contains(string(acc), marker) {
				return string(acc)
			}
		}
		if err != nil {
			return string(acc)
		}
	}
}

// readSSEUntilSentinel publishes a fresh public envelope on topic — AFTER
// every event the caller has already notified — then blocks until that
// sentinel's own marker arrives (or resp's request context ends), and
// returns everything accumulated so far.
//
// Cold review's RISK 10: the previous version of the two absence tests
// below proved "the private envelope never arrived" solely by letting
// subscribeSSE's fixed context timeout (500ms) run out and checking what
// had accumulated by then — correct today, but the proof is only as good
// as that guessed window; a slow CI runner or GC pause could let it expire
// before a real leak had time to manifest, silently passing either way. A
// subscriber's channel delivers in emission order (handleSubscribe,
// sse.go), so observing a sentinel published after the event under test
// proves that event has already been delivered or permanently skipped —
// the pipeline's own progress is the proof, not a guess at how long that
// takes.
func readSSEUntilSentinel(t *testing.T, srv *Server, resp *http.Response, topic string) string {
	t.Helper()
	marker := fmt.Sprintf("sentinel-%d", time.Now().UnixNano())
	key, _ := ec.NewPrivateKey()
	sentinel := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"sentinel":"` + marker + `"}`, Timestamp: time.Now().Unix()}
	sentinel.Sign(key)
	srv.NotifyEnvelope(sentinel)

	body := readSSEUntilContains(resp, marker)
	if !strings.Contains(body, marker) {
		t.Fatalf("sentinel envelope never arrived over SSE — cannot prove the earlier event's absence this way; got:\n%s", body)
	}
	return body
}

// subscribeSSE issues a GET /data/subscribe request against a real server,
// asserts 200, and returns the response for the caller to read from. host
// MUST be "localhost" to match a challenge obtained via getChallenge (which
// binds to req.Host="localhost"); callers with no x402 proof can pass "".
func subscribeSSE(t *testing.T, ts *httptest.Server, path, host string, setHeaders func(*http.Request)) (*http.Response, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	req, err := http.NewRequestWithContext(ctx, "GET", ts.URL+path, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	if setHeaders != nil {
		setHeaders(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("subscribe request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body := readSSEUntilContains(resp, "")
		resp.Body.Close()
		cancel()
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	return resp, cancel
}

// TestSubscribePayerOmitsPrivateEnvelope: a verified payment admits the SSE
// subscription and a public envelope streams through normally, but a
// private envelope on the same topic never reaches the paying subscriber.
func TestSubscribePayerOmitsPrivateEnvelope(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const topic = "sse:private"
	path := "/data/subscribe?topic=" + topic
	ch := getChallenge(t, srv, "GET", path)
	proofB64 := buildProof(t, ch, 200, testPayeeScript(t))

	resp, cancel := subscribeSSE(t, ts, path, "localhost", func(r *http.Request) {
		r.Header.Set(HeaderX402Proof, proofB64)
	})
	defer cancel()
	defer resp.Body.Close()

	waitForSSESubscription(t, srv, topic)

	pubKey, _ := ec.NewPrivateKey()
	pubEnv := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"ok":"public-arrived"}`, Timestamp: time.Now().Unix()}
	pubEnv.Sign(pubKey)
	srv.NotifyEnvelope(pubEnv)

	if body := readSSEUntilContains(resp, "public-arrived"); !strings.Contains(body, "public-arrived") {
		t.Fatalf("expected the public envelope to arrive over SSE; got:\n%s", body)
	}

	privKey, _ := ec.NewPrivateKey()
	privEnv := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"secret":"sse-leak-check"}`, Timestamp: time.Now().Unix(), Private: true}
	privEnv.Sign(privKey)
	srv.NotifyEnvelope(privEnv)

	if body := readSSEUntilSentinel(t, srv, resp, topic); strings.Contains(body, "sse-leak-check") {
		t.Fatal("a verified payment must not stream a private envelope over /data/subscribe")
	}
}

// TestSubscribeOperatorSeesPrivateEnvelope: the operator's bearer token
// sees a private envelope over SSE, same as it would via GET /data. SSE
// redaction that dropped private unconditionally — ignoring authed — would
// make the operator lose it too.
func TestSubscribeOperatorSeesPrivateEnvelope(t *testing.T) {
	srv := testServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const topic = "sse:operator-private"
	resp, cancel := subscribeSSE(t, ts, "/data/subscribe?topic="+topic, "", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer test-token")
	})
	defer cancel()
	defer resp.Body.Close()

	waitForSSESubscription(t, srv, topic)

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"secret":"operator-should-see-this"}`, Timestamp: time.Now().Unix(), Private: true}
	env.Sign(key)
	srv.NotifyEnvelope(env)

	body := readSSEUntilContains(resp, "operator-should-see-this")
	if !strings.Contains(body, "operator-should-see-this") {
		t.Fatalf("operator should see a private envelope over SSE; got:\n%s", body)
	}
}

// TestSubscribePayerSeesUnredactedMonetizedContent: a verified payment
// still unlocks monetized PUBLIC content over SSE, unredacted, when it covers
// the envelope by the envelope's own monetization: one of its outputs pays
// the envelope's own payee at least its own price. Here the envelope's payee
// is the script the proof pays.
func TestSubscribePayerSeesUnredactedMonetizedContent(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const topic = "sse:monetized"
	path := "/data/subscribe?topic=" + topic
	ch := getChallenge(t, srv, "GET", path)
	proofB64 := buildProof(t, ch, 200, testPayeeScript(t))

	resp, cancel := subscribeSSE(t, ts, path, "localhost", func(r *http.Request) {
		r.Header.Set(HeaderX402Proof, proofB64)
	})
	defer cancel()
	defer resp.Body.Close()

	waitForSSESubscription(t, srv, topic)

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type: "data", Topic: topic, Payload: `{"premium":"payer-should-see-this"}`,
		Timestamp:    time.Now().Unix(),
		Monetization: &envelope.Monetization{Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: testPayeeScript(t), PriceSats: 10},
	}
	env.Sign(key)
	srv.NotifyEnvelope(env)

	body := readSSEUntilContains(resp, "payer-should-see-this")
	if strings.Contains(body, "paid content") {
		t.Fatalf("a verified payment should unlock monetized SSE content, got redaction placeholder:\n%s", body)
	}
	if !strings.Contains(body, "payer-should-see-this") {
		t.Fatalf("expected the unredacted monetized payload over SSE; got:\n%s", body)
	}
}

// mintAppToken signs a credential for topic using key, in the
// <signature_hex>:<timestamp_unix> format TokenGate.verifyToken expects.
func mintAppToken(key *ec.PrivateKey, topic string) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	digest := sha256.Sum256([]byte(topic + ":" + ts))
	sig, _ := key.Sign(digest[:])
	return hex.EncodeToString(sig.Serialize()) + ":" + ts
}

// TestSubscribeAppTokenOmitsPrivateEnvelope: a validated app token admits
// the SSE subscription (Model 4, token-gated topic) and the topic's public
// declaration streams normally, but a later private envelope on that exact
// same topic never reaches the subscriber. isAuthed — the only signal that
// gates a `private` envelope — never consults the app-token context; only
// the operator bearer token does.
func TestSubscribeAppTokenOmitsPrivateEnvelope(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	const topic = "sse:appgated-private-mixed"

	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: topic, Payload: `{"tier":"public"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd", TTL: 300, Timestamp: time.Now().Unix(),
		Monetization: &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex},
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	path := "/data/subscribe?topic=" + topic
	resp, cancel := subscribeSSE(t, ts, path, "", func(r *http.Request) {
		r.Header.Set("X-App-Token", mintAppToken(appKey, topic))
	})
	defer cancel()
	defer resp.Body.Close()

	waitForSSESubscription(t, srv, topic)

	privKey, _ := ec.NewPrivateKey()
	privEnv := &envelope.Envelope{Type: "data", Topic: topic, Payload: `{"secret":"app-token-sse-leak-check"}`, Timestamp: time.Now().Unix(), Private: true}
	privEnv.Sign(privKey)
	srv.NotifyEnvelope(privEnv)

	if body := readSSEUntilSentinel(t, srv, resp, topic); strings.Contains(body, "app-token-sse-leak-check") {
		t.Fatal("a validated app token must not stream a private envelope over /data/subscribe")
	}
}

// TestSubscribeAppTokenSeesUnredactedMonetizedContent: a validated app token
// unlocks monetized PUBLIC content over SSE, unredacted, on exactly the
// topic it was validated for — the same admission credential that already
// let the subscription through the token gate. A mutation that drops the
// app-token unredaction branch in handleSubscribe would make this
// subscriber's own paid-for content come back redacted.
func TestSubscribeAppTokenSeesUnredactedMonetizedContent(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())
	const topic = "sse:appgated-monetized"

	srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
		Type: "data", Topic: topic, Payload: `{"tier":"public"}`,
		Pubkey:    "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		Signature: "3045022100abcd", TTL: 300, Timestamp: time.Now().Unix(),
		Monetization: &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex},
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	path := "/data/subscribe?topic=" + topic
	resp, cancel := subscribeSSE(t, ts, path, "", func(r *http.Request) {
		r.Header.Set("X-App-Token", mintAppToken(appKey, topic))
	})
	defer cancel()
	defer resp.Body.Close()

	waitForSSESubscription(t, srv, topic)

	pubKey, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type: "data", Topic: topic, Payload: `{"premium":"app-token-should-see-this"}`,
		Timestamp:    time.Now().Unix(),
		Monetization: &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: appPubHex, PriceSats: 10},
	}
	env.Sign(pubKey)
	srv.NotifyEnvelope(env)

	body := readSSEUntilContains(resp, "app-token-should-see-this")
	if strings.Contains(body, "paid content") {
		t.Fatalf("a validated app token should unlock monetized SSE content on its own topic, got redaction placeholder:\n%s", body)
	}
	if !strings.Contains(body, "app-token-should-see-this") {
		t.Fatalf("expected the unredacted monetized payload over SSE; got:\n%s", body)
	}
}
