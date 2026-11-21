package api

import (
	"net/http"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// mustRedactEnvelope reports whether env's own monetization hides its payload
// unless the request meets that rule (ownRuleCovered): any envelope priced
// above zero, and a token-model envelope whatever its price. Token-model
// monetization (envelope.Monetization.Validate) never requires PriceSats, so a
// rule on PriceSats alone would serve a token-model payload to a caller with
// no token. The node's own price is a separate rule (nodePriced,
// node_price_context.go).
func mustRedactEnvelope(env *envelope.Envelope) bool {
	if env.Monetization == nil {
		return false
	}
	return env.Monetization.PriceSats > 0 || env.Monetization.Model == envelope.MonetizationToken
}

// envelopeForRequest returns env as the request r may see it: env itself, or
// a copy whose payload is the redaction placeholder. GET /data (handlers.go)
// and the SSE subscription (sse.go) serve every envelope through it. authed is
// the operator bearer token (Server.isAuthed), which sees every payload. A
// `private` envelope never gets here for anyone else: both callers drop it
// first.
func envelopeForRequest(r *http.Request, env *envelope.Envelope, authed bool) *envelope.Envelope {
	if authed || envelopeCovered(r, env) {
		return env
	}
	redacted := *env
	redacted.Payload = envelopeRedactionPlaceholder(env)
	return &redacted
}

// envelopeCovered reports whether r unlocks env, decided for each envelope
// rather than once for the request. env must meet both of its rules:
//
//   - Its own monetization (ownRuleCovered), when that hides its payload
//     (mustRedactEnvelope).
//   - The node's own price, when env is node-priced (nodePriced): an
//     unmonetized, free-model or split envelope needs a verified payment that
//     pays the node's own payee script at least the price the gate recorded
//     for the route (nodePriceCovered, node_price_context.go). A free node,
//     or a route the node does not price, records no price.
//
// So a split envelope needs both its app's share and the node's, a passthrough
// envelope needs only its app's, and a token-model envelope needs only its
// token. No other envelope's rule, the newest one's included, waives either.
func envelopeCovered(r *http.Request, env *envelope.Envelope) bool {
	if mustRedactEnvelope(env) && !ownRuleCovered(r, env) {
		return false
	}
	return !nodePriced(env) || nodePriceCovered(r)
}

// ownRuleCovered reports whether r meets env's own monetization rule:
//
//   - A token-model envelope needs an app token validated on its exact topic
//     and issued by the AuthPubkey its own rule names
//     (app_token_issuer_context.go). A payment never unlocks one.
//   - A priced envelope needs a verified payment with one output that pays
//     its own payee script at least its own price, capped as the node caps
//     app prices (paymentCovers, paid_outputs_context.go). A payment to the
//     node's script never pays an app's price.
func ownRuleCovered(r *http.Request, env *envelope.Envelope) bool {
	mon := env.Monetization
	if mon.Model == envelope.MonetizationToken {
		return appTokenTopicMatches(r, env.Topic) && appTokenIssuerMatches(r, mon.AuthPubkey)
	}
	return paymentCovers(r, mon.PayeeLockingScriptHex, mon.PriceSats)
}

// envelopeRedactionPlaceholder is the payload substituted for a redacted
// envelope: the existing wording for a priced payload (kept verbatim so
// existing clients and tests that match on "paid content" are unaffected),
// and more accurate wording for a Model 4 envelope with no valid token,
// which was never about payment at all.
func envelopeRedactionPlaceholder(env *envelope.Envelope) string {
	if env.Monetization != nil && env.Monetization.Model == envelope.MonetizationToken {
		return "[token-gated content — access via X-App-Token]"
	}
	return "[paid content — access via HTTP 402]"
}
