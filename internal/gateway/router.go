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
	"strings"
)

// Router sends each request to the node's API or to a site's handler, by
// Host header, so one listener can serve both (decision 2; D1 fix).
//
//   - A Host equal to APIHost, or a loopback name (localhost, an IPv4
//     literal in 127.0.0.0/8, or ::1), reaches API. The loopback rule
//     keeps the local CLI and doctor working on a gateway node — they
//     reach the API at http://127.0.0.1:9333 and http://localhost:9333
//     (cmd/anvil/doctor.go:958, help.go:41-53) — and adds no exposure,
//     since the API is already public at APIHost. An empty APIHost is
//     NEVER a wildcard: with no APIHost configured, only a loopback Host
//     reaches API — everything else is Sites' call (fail closed).
//   - Any other Host is Sites' call: SiteHandler itself 404s a Host that
//     isn't an allowed site (see site.go's Policy check), which is how
//     "anything else: a plain 404" is actually reached — Router makes no
//     second allow-check of its own, so there is exactly one TXT lookup
//     path per request, not two.
//
// API is the existing API handler this wraps — srv.Handler(), the hook
// internal/api exports unchanged for exactly this purpose. Sites is
// nil-safe: a nil Sites 404s everything that isn't APIHost or loopback,
// which is only ever the case in a test or a degenerate wiring;
// cmd/anvil's real wiring always builds a SiteHandler when [gateway] is
// on, and internal/config's Load requires a non-empty api_host whenever
// [gateway] is enabled (D2), so an empty APIHost in production only ever
// means gateway mode is off (no Router constructed at all).
type Router struct {
	API     http.Handler
	Sites   *SiteHandler
	APIHost string
}

// ServeHTTP implements http.Handler.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	apiHost := normalizeHost(rt.APIHost)
	if (apiHost != "" && host == apiHost) || isLoopbackHost(host) {
		rt.API.ServeHTTP(w, r)
		return
	}
	if rt.Sites == nil {
		http.NotFound(w, r)
		return
	}
	rt.Sites.ServeHTTP(w, r)
}

// normalizeHost applies D1's Host normalisation — lower-case, strip an
// optional ":port" suffix (handling a bracketed IPv6 literal with no port
// too), then strip one trailing dot — so a request's Host header, a
// configured api_host and a sites-file domain entry all compare equal
// regardless of case or a trailing dot (review R1, R2). Router, Policy and
// SiteHandler all normalise through this one function.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

// isLoopbackHost reports whether host (already normalised) is one of D1's
// loopback names: "localhost", an IPv4 literal in 127.0.0.0/8, or ::1.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
