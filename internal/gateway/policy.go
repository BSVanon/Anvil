package gateway

import "context"

// Policy is decision 3's one allow rule: whether host may be served, and
// the origin its TXT names. B7a uses it to decide what to serve; B9 gates
// certificate issuance on it, and B8 gates version/seq tracking scope on
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
// per decision 3. A Host with no domain entry only triggers a TXT lookup
// when the sites file lists any "origin" entries at all — and even then,
// subject to the resolver's global flood guard (decision 4) — since
// otherwise an arbitrary Host header can never possibly match anything in
// the sites file and a lookup would be pure resolver load with no chance
// of a hit.
func (p *Policy) Allowed(ctx context.Context, host string) (origin string, ok bool) {
	snap := p.sites.Snapshot()
	hasDomain := snap.HasDomain(host)
	if !hasDomain && !snap.HasAnyOrigin() {
		return "", false
	}
	if !hasDomain && !p.txt.AllowSpeculative() {
		return "", false
	}

	origin, ok = p.txt.Lookup(ctx, host)
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
