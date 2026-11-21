package config

// DefaultHeaderFallbackPeers returns a copy of the canonical, baked-in
// header-fallback peer list (config.go's own defaultHeaderFallbackPeers).
// Exported so a caller outside this package can compare against every
// baked-in default rather than keeping its own hardcoded copy, which
// would silently fall out of step if this package's list ever grows past
// its current single entry.
func DefaultHeaderFallbackPeers() []string {
	out := make([]string, len(defaultHeaderFallbackPeers))
	copy(out, defaultHeaderFallbackPeers)
	return out
}

// IsDefaultHeaderFallbackPeer reports whether url is one of the baked-in
// canonical header-fallback peers, compared exactly as
// ensureHeaderFallbackPeers appends it (no extra normalisation).
func IsDefaultHeaderFallbackPeer(url string) bool {
	for _, p := range defaultHeaderFallbackPeers {
		if p == url {
			return true
		}
	}
	return false
}
