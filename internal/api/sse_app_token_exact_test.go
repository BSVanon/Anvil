package api

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestSubscribeAppTokenMismatchedTopicStaysRedacted: an SSE-level
// regression test for the app-token redaction check on handleSubscribe's
// event loop (sse.go, through envelopeForRequest), distinct from
// TestAppTokenTopicMatchesExactTopicOnly (app_token_context_test.go), which
// only covers appTokenTopicMatches itself in isolation. A mutation at the
// call site (e.g. swapping the exact-match helper for a prefix check, or
// dropping the call entirely) would make this test fail even if the helper
// function's own unit test still passed.
//
// TokenGate.Middleware (token_gate.go) can never hand handleSubscribe a
// context whose validated topic differs from the subscription's own query
// topic: verifyToken re-derives the signed message from the topic it is
// asked to check against, so a token signed for topic A can never verify
// when checked against topic B. The only way to exercise the mismatched
// case at all — and so the only way to test that handleSubscribe's
// exact-match call is what is actually closing it, not just happy
// circumstance — is to bypass TokenGate.Middleware and inject the
// mismatched context value directly, the same unforgeable mechanism
// Middleware itself would use (app_token_context.go).
//
// This talks to Server.Handler() directly through an httptest.ResponseRecorder
// rather than a real loopback connection (contrast subscribeSSE,
// sse_private_test.go) because a context value set on a client-side
// request is never transmitted over an actual HTTP connection — the server
// builds its own fresh *http.Request from the wire, with no way to carry a
// Go context value across it. Reading w.Body only after the handler
// goroutine has signaled completion over the done channel (a happens-before
// edge, like every other synchronization in this package's SSE tests)
// keeps this race-free despite using a ResponseRecorder.
func TestSubscribeAppTokenMismatchedTopicStaysRedacted(t *testing.T) {
	srv := testServer(t) // no tokenGate configured — nothing but the redaction check itself can gate this
	const topic = "sse:exact-match"

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/data/subscribe?topic="+topic, nil).WithContext(ctx)
	req.Host = "localhost"
	// Simulate a validated app token for a DIFFERENT topic than this
	// subscription's own — unreachable through the real TokenGate.Middleware
	// (see doc comment above), so this is the only way to reach the
	// mismatched branch of handleSubscribe's own exact-match check.
	req = req.WithContext(withAppTokenTopic(req.Context(), "sse:other-topic"))

	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()

	waitForSSESubscription(t, srv, topic)

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type: "data", Topic: topic, Payload: `{"premium":"should-stay-redacted"}`,
		Timestamp:    time.Now().Unix(),
		Monetization: &envelope.Monetization{Model: envelope.MonetizationToken, AuthPubkey: hex.EncodeToString(key.PubKey().Compressed())},
	}
	env.Sign(key)
	srv.NotifyEnvelope(env)

	<-done // handler returns once ctx's deadline passes; synchronizes its writes to w before we read w.Body below

	body := w.Body.String()
	if strings.Contains(body, "should-stay-redacted") {
		t.Fatalf("an app-token context validated for a different topic must not unlock this topic's own token-gated payload over SSE; got:\n%s", body)
	}
	if !strings.Contains(body, "token-gated content") {
		t.Fatalf("expected the token-gated redaction placeholder over SSE; got:\n%s", body)
	}
}
