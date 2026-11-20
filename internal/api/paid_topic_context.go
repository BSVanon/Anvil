package api

import (
	"context"
	"net/http"
)

// paidTopicContextKey is the request-context key for the exact topic a
// verified x402 payment (paid_context.go's withPaid) was resolved and
// charged against.
//
// Like paidContextKey, a context value cannot be set, read, or forged by a
// client — only payment.go's Middleware ever calls withPaidTopic, and only
// alongside withPaid, once a proof or direct payment has actually verified.
//
// isAuthedOrPaid's *paid* signal is request-scoped: one verified payment
// admits the whole request. GET /data and SSE return every envelope whose
// Topic shares the queried topic as a prefix (envelope/store.go's durable
// scan, documented for listing — docs/ANVIL_CAPABILITIES.md), so a single
// admission payment must not be read as having paid for every envelope the
// prefix scan happens to surface: cold review's RISK 4 found that paying a
// cheap toll on a parent topic unredacted an expensive sibling/child
// envelope's own, separately-priced payload, because the redaction check
// only asked "was this request paid at all," never "paid for THIS
// envelope's own topic."
//
// resolvePayees (payment_resolve.go, after the item-9 exact-topic fix on
// Resolve) always resolves and charges against the queried topic's own
// exact monetization — so a verified payment for topic T demonstrably
// covers T's own declared payee and price, never a sibling or sub-topic's.
// paidTopicMatches lets the per-envelope redaction check (handlers.go,
// sse.go) require exactly that match.
type paidTopicContextKey struct{}

// withPaidTopic returns ctx carrying the exact topic this request's
// verified payment was resolved and charged against.
func withPaidTopic(ctx context.Context, topic string) context.Context {
	return context.WithValue(ctx, paidTopicContextKey{}, topic)
}

// paidTopicMatches reports whether r's verified payment (if any) was
// resolved and charged against exactly topic — never a prefix match, never
// a different topic.
func paidTopicMatches(r *http.Request, topic string) bool {
	paidTopic, ok := r.Context().Value(paidTopicContextKey{}).(string)
	return ok && topic != "" && paidTopic == topic
}
