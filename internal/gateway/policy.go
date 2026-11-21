package gateway

import "context"

// Policy is the allow rule: whether a host may be served and the origin its
// TXT record names. It decides what to serve, gates certificate issuance, and
// gates version and sequence tracking scope on
// it — there is exactly one allow rule in the whole gateway mechanism, so
// every brick agrees on what is actually being served.
//
// A host is allowed when the sites file has a "domain" entry for it, or
// when the origin its TXT names has an "origin" entry. Either way, the
// TXT record is the authority for which origin is served: a listed domain
// with no valid TXT is refused, never served against a stale or assumed
// origin.
type Policy struct {
	sites *Allowlist
	txt   *Resolver
}

// NewPolicy builds a Policy over a sites allowlist and a TXT resolver.
func NewPolicy(sites *Allowlist, txt *Resolver) *Policy {
	return &Policy{sites: sites, txt: txt}
}

// Allowed reports whether host may be served, and the origin to serve,
// A Host with no domain entry only triggers a TXT lookup
// when the sites file lists any "origin" entries at all — otherwise an
// arbitrary Host header can never possibly match anything in the sites
// file and a lookup would be pure resolver load with no chance of a hit.
//
// The resolver's flood guard is not consulted here: it must
// only ever gate a genuine resolver cache miss, never a cached answer, so
// Resolver.Lookup itself checks it, after its own cache lookup and before
// the singleflighted network call — never ahead of the cache, the
// way this function used to. host's no-domain-entry status ("speculative"
// — can only possibly match through an "origin" entry, not an explicit
// "domain" one) still decides WHICH lookups the guard applies to; Lookup
// just decides WHEN, relative to its cache.
func (p *Policy) Allowed(ctx context.Context, host string) (origin string, ok bool) {
	host = normalizeHost(host)
	snap := p.sites.Snapshot()
	hasDomain := snap.HasDomain(host)
	if !hasDomain && !snap.HasAnyOrigin() {
		return "", false
	}

	origin, ok = p.txt.Lookup(ctx, host, !hasDomain)
	if !ok {
		return "", false
	}
	if hasDomain {
		return origin, true
	}
	if snap.HasOrigin(origin) {
		return origin, true
	}
	return "", false
}
