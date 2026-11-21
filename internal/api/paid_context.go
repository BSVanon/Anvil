package api

import "context"

// paidContextKey is the request-context key for a verified x402 payment.
//
// Unlike the X-Anvil-Authed header, a context value cannot be set, read, or
// forged by a client at all — there is nothing for the trust boundary
// (Server.Handler) to strip. Only payment verification in this package
// (payment.go's Middleware) ever calls withPaid, and only after a proof or
// direct payment has actually verified.
//
// A verified payment marks a request *paid*, which is distinct from
// *authenticated* (this node's own operator bearer token, and nothing
// else — see Server.isAuthed). The marker says only that some payment
// verified. It never decides what the payment unlocks: a monetized payload
// is unlocked per envelope, by the outputs the payment carries
// (paymentCovers, paid_outputs_context.go). A payment must never unlock a
// `private` envelope or its metadata; only isAuthed gates those reads. See
// docs/ANVIL_PRIVATE_FLAG_CONTRACT.md for the full contract.
type paidContextKey struct{}

// withPaid returns ctx carrying the verified-payment marker for this request.
func withPaid(ctx context.Context) context.Context {
	return context.WithValue(ctx, paidContextKey{}, true)
}
