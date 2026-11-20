package api

import (
	"net/http"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// mustRedactEnvelope reports whether env's own payload is hidden unless the
// request unlocks it (envelopeCovered): any envelope priced above zero, and a
// token-model envelope whatever its price. Token-model monetization
// (envelope.Monetization.Validate) never requires PriceSats, so a rule on
// PriceSats alone would serve a token-model payload to a caller with no token.
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
	if authed || !mustRedactEnvelope(env) || envelopeCovered(r, env) {
		return env
	}
	redacted := *env
	redacted.Payload = envelopeRedactionPlaceholder(env)
	return &redacted
}

// envelopeCovered reports whether r unlocks env by env's own monetization
// rule, decided for each envelope rather than once for the request:
//
//   - A token-model envelope needs an app token validated on its exact topic
//     and issued by the AuthPubkey its own rule names
//     (app_token_issuer_context.go). A payment never unlocks one.
//   - A priced envelope needs a verified payment with one output that pays
//     its own payee script at least its own price, capped as the node caps
//     app prices (paymentCovers, paid_outputs_context.go). The node's own
//     toll pays the node's script, so it unlocks only what the node prices:
//     unmonetized content, which is never redacted. It never unlocks an
//     envelope priced to an app's payee.
func envelopeCovered(r *http.Request, env *envelope.Envelope) bool {
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
