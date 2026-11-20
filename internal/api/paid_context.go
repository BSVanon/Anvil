package api

import (
	"context"
	"net/http"
)

// paidContextKey is the request-context key for a verified x402 payment.
//
// Unlike the X-Anvil-Authed header, a context value cannot be set, read, or
// forged by a client at all — there is nothing for the trust boundary
// (Server.Handler) to strip. Only payment verification in this package
// (payment.go's Middleware) ever calls withPaid, and only after a proof or
// direct payment has actually verified.
//
// A verified payment marks a request *paid*, which is distinct from
// *authenticated* (operator bearer token or a valid app token, see
// Server.isAuthed). Paid unlocks paid/monetized payloads, same as today —
// see Server.isAuthedOrPaid. It must never unlock a `private` envelope or
// its metadata; only isAuthed gates those reads. See
// docs/ANVIL_PRIVATE_FLAG_CONTRACT.md for the full contract.
type paidContextKey struct{}

// withPaid returns ctx carrying the verified-payment marker for this request.
func withPaid(ctx context.Context) context.Context {
	return context.WithValue(ctx, paidContextKey{}, true)
}

// isPaid reports whether r's context carries a verified payment for this
// request. There is no client-settable header for this signal — a caller
// cannot forge it by sending any header or value.
func isPaid(r *http.Request) bool {
	paid, _ := r.Context().Value(paidContextKey{}).(bool)
	return paid
}
