package api

import "github.com/BSVanon/Anvil/internal/envelope"

// mustRedactEnvelope reports whether env's own payload must be hidden from
// an unauthenticated, unpaid, untokened caller: any monetized envelope
// priced above zero (the original rule), OR a Model 4 (token-gated)
// envelope regardless of price.
//
// handlers.go and sse.go's redaction used to gate only on PriceSats > 0.
// Token-model monetization (envelope.Monetization.Validate) never requires
// PriceSats, so a token-gated envelope reached through a parent topic's
// listing (GET /data?topic=P returning P and P:tok alike — the prefix scan
// is documented for listing, docs/ANVIL_CAPABILITIES.md) was never
// redacted at all: cold review's RISK 4, served with no token through a
// query on the parent topic. mustRedactEnvelope closes that — same for the
// token gate's own 401 on a direct query, now for every path that can
// surface the envelope.
func mustRedactEnvelope(env *envelope.Envelope) bool {
	if env.Monetization == nil {
		return false
	}
	return env.Monetization.PriceSats > 0 || env.Monetization.Model == envelope.MonetizationToken
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
