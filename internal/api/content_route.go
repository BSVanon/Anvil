package api

import "net/http"

// isAppContentRoute reports whether r targets one of the two routes whose
// response is a topic's own content: GET /data and GET /data/subscribe
// (SSE). These are the only routes an app's topic-level monetization
// (passthrough/split pricing, token gating) may ever apply to.
//
// Every other openRead route (/stats, /headers/tip, /headers/range,
// /tx/{txid}/beef, /topics, /identity/{pubkey}, /overlay/lookup, ...) also
// accepts a ?topic= query parameter, but none of them serve that topic's
// content — the parameter is irrelevant to their handler's response. Before
// this check, PaymentGate.resolvePayees (payment_resolve.go) and
// TokenGate.Middleware (token_gate.go) treated ?topic= the same way on
// every route: an app token valid for a self-created topic skipped the
// node's own toll on ANY of these node routes too (cold review BL2(a)), and
// a token-model envelope published on a topic name that happened to match
// what a legitimate caller queries could 401 them out of unrelated node
// routes entirely. Every write (POST /data, POST /broadcast) is excluded on
// method alone — a write is never "this topic's content," and the node
// toll (or operator auth) must always gate it regardless of any topic's own
// declared pricing (cold review RISK 3: passthrough self-pricing replacing
// the node's toll, writes included).
func isAppContentRoute(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	switch r.URL.Path {
	case "/data", "/data/subscribe":
		return true
	default:
		return false
	}
}
