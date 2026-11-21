package api

import "net/http"

// isAppContentRoute reports whether r targets one of the two routes whose
// response is a topic's own content: GET /data and GET /data/subscribe
// (SSE), and HEAD on either, which the mux serves with the GET handler.
// These are the only routes an app's topic-level monetization
// (passthrough/split pricing, token gating) may ever apply to.
//
// Every other openRead route (/stats, /headers/tip, /headers/range,
// /tx/{txid}/beef, /topics, /identity/{pubkey}, /overlay/lookup, ...) also
// accepts a ?topic= query parameter, but none of them serve that topic's
// content: the parameter is irrelevant to their response. So an app token
// valid for a self-created topic never skips the node's own toll there, and a
// token-model envelope on a topic name a caller happens to pass never 401s
// them out of an unrelated node route. Every write (POST /data, POST
// /broadcast) is excluded on method alone: a write is never a topic's
// content, and the node's toll (or operator auth) always gates it, whatever
// pricing a topic declares.
//
// HEAD is a content read too: the mux sends a HEAD to the GET handler, which
// answers with the same status and headers as GET, Content-Length included,
// so a HEAD outside these rules would get 200 where GET gets 401 or 402, and
// learn the size of the content.
func isAppContentRoute(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	switch r.URL.Path {
	case "/data", "/data/subscribe":
		return true
	default:
		return false
	}
}
