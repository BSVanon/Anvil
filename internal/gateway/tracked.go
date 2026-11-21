package gateway

import (
	"context"
	"sort"
)

// Origins returns the snapshot's "origin" entries, sorted.
func (s *Snapshot) Origins() []string {
	if s == nil {
		return nil
	}
	return sortedSet(s.origins)
}

// Domains returns the snapshot's "domain" entries, sorted.
func (s *Snapshot) Domains() []string {
	if s == nil {
		return nil
	}
	return sortedSet(s.domains)
}

func sortedSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TrackedOrigins returns the origins the policy allows, the set whose
// versions the node tracks: each "origin" entry, then the origin each
// "domain" entry's TXT record names, in sorted order, without repeats and
// at most limit of them. A domain whose TXT record names no origin is left
// out until it does. Its lookups go through the resolver and its cache,
// exactly as a request for that domain's site would.
func (p *Policy) TrackedOrigins(ctx context.Context, limit int) []string {
	if limit <= 0 {
		return nil
	}
	snap := p.sites.Snapshot()
	seen := make(map[string]bool)
	var out []string
	add := func(origin string) (full bool) {
		if !seen[origin] {
			seen[origin] = true
			out = append(out, origin)
		}
		return len(out) >= limit
	}
	for _, origin := range snap.Origins() {
		if add(origin) {
			return out
		}
	}
	for _, domain := range snap.Domains() {
		if ctx.Err() != nil {
			break
		}
		if origin, ok := p.txt.Lookup(ctx, domain, false); ok && add(origin) {
			break
		}
	}
	return out
}
