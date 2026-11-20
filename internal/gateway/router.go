// Package gateway implements Anvil's gateway mechanism (the B7 brick's
// architecture decisions 1-9): a host-based Router that serves either the
// node's existing API or a publisher's own domain, resolving which origin
// a domain serves through the ORDFS DNS TXT convention, gated by an
// operator-maintained sites allowlist.
//
// With [gateway] off, nothing in this package is constructed at all — see
// cmd/anvil's wiring helper — so a standard node's behaviour, config and
// output stay byte-for-byte what they are today.
//
// Three seams exist for the bricks that build on this one (decision 9):
//
//   - Versions (versions.go) — B8 (BRC-159 tip tracking) constructs its
//     own implementation in place of DefaultVersions and the wiring swaps
//     it in; nothing here or in SiteHandler needs to change.
//   - Policy (policy.go) — B8 (version/seq tracking scope) and B9
//     (certificate issuance) both gate on Policy.Allowed, so there is
//     exactly one allow rule for the whole mechanism.
//   - Router (this file) — B9 mounts the same Router on 443/80 once it
//     adds TLS; B7a mounts it only on the existing :9333 API listener.
package gateway

import (
	"net"
	"net/http"
)

// Router sends each request to the node's API or to a site's handler, by
// Host header, so one listener can serve both (decision 2).
//
//   - A Host equal to APIHost reaches API. APIHost left empty matches
//     every Host that Sites doesn't claim — today's behaviour on the
//     existing :9333 listener, where local tools, mesh peers and tests
//     send all kinds of Host headers and must keep reaching the API. B9
//     sets APIHost to a specific admin hostname when it mounts this
//     Router on 443/80, so those public ports don't default-expose the
//     full API to an arbitrary Host.
//   - Any other Host is Sites' call: SiteHandler itself 404s a Host that
//     isn't an allowed site (see site.go's Policy check), which is how
//     "anything else: a plain 404" is actually reached — Router makes no
//     second allow-check of its own, so there is exactly one TXT lookup
//     path per request, not two.
//
// API is the existing API handler this wraps — srv.Handler(), the hook
// internal/api exports unchanged for exactly this purpose. Sites is
// nil-safe: a nil Sites 404s everything that isn't APIHost, which is only
// ever the case in a test or a degenerate wiring; cmd/anvil's real wiring
// always builds a SiteHandler when [gateway] is on.
type Router struct {
	API     http.Handler
	Sites   *SiteHandler
	APIHost string
}

// ServeHTTP implements http.Handler.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if rt.APIHost == "" || host == rt.APIHost {
		rt.API.ServeHTTP(w, r)
		return
	}
	if rt.Sites == nil {
		http.NotFound(w, r)
		return
	}
	rt.Sites.ServeHTTP(w, r)
}

// hostOnly strips an optional ":port" suffix from a Host header, the way
// api_host and the sites file name hosts (no port).
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
