package api

import (
	"context"
	"net/http"
	"strings"
)

// appTokenIssuerKey is the request-context key for the key that issued a
// validated app token: the AuthPubkey of the topic rule TokenGate.Middleware
// (token_gate.go) validated it against. Like the token's topic
// (app_token_context.go), it is a context value a client can neither set nor
// read.
//
// A token-model envelope unredacts only for a token validated on its own
// exact topic and issued by the key its own rule names (envelopeCovered,
// envelope_redaction.go). A token issued under a newer token-model envelope
// on the same topic therefore unlocks only the envelopes that name the same
// issuer, never an older envelope another key published there.
type appTokenIssuerKey struct{}

// withAppTokenIssuer returns ctx carrying the hex AuthPubkey that issued the
// request's validated app token.
func withAppTokenIssuer(ctx context.Context, authPubkeyHex string) context.Context {
	return context.WithValue(ctx, appTokenIssuerKey{}, strings.ToLower(authPubkeyHex))
}

// appTokenIssuerMatches reports whether r carries a validated app token
// issued by authPubkeyHex, ignoring hex case.
func appTokenIssuerMatches(r *http.Request, authPubkeyHex string) bool {
	issuer, _ := r.Context().Value(appTokenIssuerKey{}).(string)
	return issuer != "" && issuer == strings.ToLower(authPubkeyHex)
}
