package api

import (
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TestMustRedactEnvelope covers every branch cold review's RISK 4 found
// missing: a Model 4 (token-gated) envelope with no price set at all used
// to fall through both handlers.go's and sse.go's redaction check entirely
// (PriceSats > 0 was the only test), serving its payload unredacted to any
// caller with no token whatsoever.
func TestMustRedactEnvelope(t *testing.T) {
	cases := []struct {
		name string
		mon  *envelope.Monetization
		want bool
	}{
		{"no monetization", nil, false},
		{"free model", &envelope.Monetization{Model: envelope.MonetizationFree}, false},
		{"priced passthrough", &envelope.Monetization{Model: envelope.MonetizationPassthrough, PriceSats: 10}, true},
		{"zero-priced passthrough", &envelope.Monetization{Model: envelope.MonetizationPassthrough, PriceSats: 0}, false},
		{"token model, zero price", &envelope.Monetization{Model: envelope.MonetizationToken, PriceSats: 0}, true},
		{"token model, priced", &envelope.Monetization{Model: envelope.MonetizationToken, PriceSats: 10}, true},
	}
	for _, c := range cases {
		env := &envelope.Envelope{Topic: "t", Monetization: c.mon}
		if got := mustRedactEnvelope(env); got != c.want {
			t.Errorf("%s: mustRedactEnvelope() = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestEnvelopeRedactionPlaceholderWording: existing clients and tests match
// on the literal "paid content" wording for a priced payload (kept
// verbatim) — a Model 4 envelope gets its own, more accurate wording since
// it was never about payment at all.
func TestEnvelopeRedactionPlaceholderWording(t *testing.T) {
	priced := &envelope.Envelope{Monetization: &envelope.Monetization{Model: envelope.MonetizationPassthrough, PriceSats: 10}}
	if got := envelopeRedactionPlaceholder(priced); !strings.Contains(got, "paid content") {
		t.Errorf("expected the existing 'paid content' wording for a priced payload, got %q", got)
	}

	tokenGated := &envelope.Envelope{Monetization: &envelope.Monetization{Model: envelope.MonetizationToken}}
	if got := envelopeRedactionPlaceholder(tokenGated); !strings.Contains(got, "token-gated") {
		t.Errorf("expected token-gated wording for a Model 4 envelope, got %q", got)
	}
}
