package api

import (
	"context"
	"net/http"
)

// appTokenTopicKey is the request-context key for a validated app token's
// topic.
//
// Like paidContextKey (paid_context.go), a context value cannot be set,
// read, or forged by a client — there is nothing for the trust boundary to
// strip. Only TokenGate.Middleware (token_gate.go) ever calls
// withAppTokenTopic, and only after a signature and timestamp have actually
// verified against the topic's declared AuthPubkey.
//
// A validated app token is a credential for monetized PUBLIC content on the
// exact topic it was validated for — see appTokenTopicMatches. It is never
// "authenticated" (Server.isAuthed/isOperatorToken, auth.go) and never
// unlocks a `private` envelope or its metadata, on this topic or any other.
// See docs/API_REFERENCE.md, section Private envelopes, for the full contract.
type appTokenTopicKey struct{}

// withAppTokenTopic returns ctx carrying the topic T that this request's
// X-App-Token was validated against.
func withAppTokenTopic(ctx context.Context, topic string) context.Context {
	return context.WithValue(ctx, appTokenTopicKey{}, topic)
}

// appTokenTopicMatches reports whether r's context carries a validated app
// token for EXACTLY the given topic — never a prefix match, never a
// different topic. Used to skip the x402 toll (payment.go) and to unredact a
// monetized payload (handlers.go, sse.go) for a Model 4 (token-gated) topic;
// never used to gate a `private` envelope.
func appTokenTopicMatches(r *http.Request, topic string) bool {
	t, _ := r.Context().Value(appTokenTopicKey{}).(string)
	return topic != "" && t == topic
}
