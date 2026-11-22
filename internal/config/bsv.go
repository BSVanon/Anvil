package config

import (
	"net/url"
	"strings"
)

const defaultHeaderStaleAfterSecs = 1800

type BSVConfig struct {
	Nodes []string `toml:"nodes"`
	// HeaderSyncIntervalSecs is how often the node polls its BSV peers for new
	// block headers. Lower = tighter tip tracking (headers agree with canonical
	// sooner and orphans reorg out faster) at the cost of more frequent P2P
	// handshakes. 0 or unset → default 30s (down from the historic 120s).
	HeaderSyncIntervalSecs int `toml:"header_sync_interval_secs"`
	// HeaderStaleAfterSecs is the maximum age of the stored tip header before a
	// trusted HTTPS fallback is consulted even when a BSV P2P peer is connected.
	// 0 or unset → default 1800s.
	HeaderStaleAfterSecs int `toml:"header_stale_after_secs"`

	// HeaderFallbackPeers are HTTPS base URLs of TRUSTED Anvil nodes (e.g.
	// "https://anvil.sendbsv.com") this node pulls headers from when its BSV P2P
	// peers are all unreachable or the stored tip is stale — the mesh header
	// self-heal. A canonical default (defaultHeaderFallbackPeers) is baked into
	// the binary and appended here on load, so the self-heal is active after
	// `anvil upgrade` with NO config edit —
	// the same posture as the default BSV P2P seeds. Operators may prepend their
	// own trusted peers (tried first) or turn the fallback off entirely with
	// HeaderFallbackDisabled. TRUST MODEL — headers fetched from these peers are
	// applied through the same validation as BSV P2P headers (per-header PoW: hash
	// ≤ stated target, prev-hash linkage, cumulative most-work) but NOT full
	// difficulty-adjustment (DAA) or a min-difficulty floor, so a source could in
	// principle feed an easy-difficulty chain. This is the standard SPV-header
	// trust model — you trust the (few, baked-in or operator-listed) peers, which
	// is why the source is a fixed default, NOT auto-discovered from the gossip
	// mesh: a SHIP/SLAP-advertised peer is not trust-qualified for header authority.
	HeaderFallbackPeers []string `toml:"header_fallback_peers"`

	// HeaderFallbackDisabled turns the mesh header self-heal off entirely (no
	// default peer, no operator peers). Left false, the baked-in default applies.
	// An operator only needs this to opt a node out of consulting any HTTPS header
	// fallback (e.g. a node that must never reach outside its own BSV P2P peers).
	HeaderFallbackDisabled bool `toml:"header_fallback_disabled"`
}

// defaultBSVSeeds is the canonical set of BSV P2P peers the header syncer pulls
// block headers from. The syncer (cmd/anvil/main.go) tries each in order and
// rotates to the next on any failure, so it needs more than one to survive a
// single flaky peer dropping the version handshake. These are appended as
// fallbacks to whatever the operator configured — which also repairs older
// single-peer configs written by earlier `anvil deploy` templates, at runtime,
// with no config edit needed on upgrade.
var defaultBSVSeeds = []string{
	"seed.bitcoinsv.io:8333",
	"seed.satoshisvision.network:8333",
}

// isTrustedHeaderPeerURL reports whether a header_fallback_peers entry is safe to
// trust as a header source. This feature deliberately omits DAA / max-target
// consensus validation, so the transport MUST be authenticated (https) — a
// plaintext peer would let a network MITM substitute the header stream, turning
// transport into header authority. An explicit loopback http URL is allowed for
// local/dev use only.
func isTrustedHeaderPeerURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	// A header peer is an API base URL (an optional path prefix is allowed, e.g.
	// https://host/anvil); a query or fragment is never valid and is rejected.
	if u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return true
		}
	}
	return false
}

// FilterTrustedHeaderPeers splits header_fallback_peers into entries safe to use
// (https, or loopback http for dev) and rejected ones, so the caller can warn
// about insecure/malformed peers loudly without ever trusting them.
func FilterTrustedHeaderPeers(peers []string) (valid, rejected []string) {
	for _, p := range peers {
		if isTrustedHeaderPeerURL(p) {
			valid = append(valid, strings.TrimSpace(p))
		} else {
			rejected = append(rejected, p)
		}
	}
	return valid, rejected
}

// ensureFallbackSeeds returns the operator-configured peers with any missing
// canonical seeds appended (deduped, order-preserving). Configured peers are
// tried first; the defaults act purely as fallbacks, so a node whose config
// lists a single (possibly flaky) peer always has others to rotate to.
func ensureFallbackSeeds(nodes []string) []string {
	seen := make(map[string]bool, len(nodes)+len(defaultBSVSeeds))
	out := make([]string, 0, len(nodes)+len(defaultBSVSeeds))
	for _, n := range nodes {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, s := range defaultBSVSeeds {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// defaultHeaderFallbackPeers is the canonical set of TRUSTED Anvil nodes a node
// pulls block headers from over HTTPS when its BSV P2P header sync is down — the
// mesh header self-heal. Like defaultBSVSeeds, these ship in the binary so the
// self-heal is active after `anvil upgrade` with no per-node config edit. Same
// trust posture as the default P2P seeds: baked into the installed binary,
// operator-overridable, and NOT auto-discovered from untrusted gossip. The
// fallback is consulted only when every P2P peer failed a sync round (see
// cmd/anvil/main.go), so a healthy node never calls these.
var defaultHeaderFallbackPeers = []string{
	"https://anvil.sendbsv.com",
}

// ensureHeaderFallbackPeers returns the operator-configured header peers with the
// canonical defaults appended (deduped, order-preserving) — operator peers are
// tried first. Any entry whose host matches selfPublicURL is dropped so a node
// never header-syncs from itself (notably the default node, which is its own
// public URL). If disabled is true the fallback is off entirely (returns nil),
// honoring an explicit operator opt-out.
//
// If suppressDefault is true ([overlay] named_peers is set — closed network),
// the baked-in default peer is never appended, so a closed-network node never
// contacts it; the operator's own peers list still applies as-is, so a node
// that wants the HTTPS header catch-up in closed-network mode lists its own
// trusted peers explicitly instead of relying on the public default.
func ensureHeaderFallbackPeers(peers []string, selfPublicURL string, disabled, suppressDefault bool) []string {
	if disabled {
		return nil
	}
	selfHost := ""
	if u, err := url.Parse(strings.TrimSpace(selfPublicURL)); err == nil {
		selfHost = strings.ToLower(u.Hostname())
	}
	seen := make(map[string]bool, len(peers)+len(defaultHeaderFallbackPeers))
	out := make([]string, 0, len(peers)+len(defaultHeaderFallbackPeers))
	add := func(list []string) {
		for _, p := range list {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			if selfHost != "" {
				if u, err := url.Parse(p); err == nil && strings.ToLower(u.Hostname()) == selfHost {
					continue // never header-sync from ourselves
				}
			}
			out = append(out, p)
		}
	}
	add(peers)
	if !suppressDefault {
		add(defaultHeaderFallbackPeers)
	}
	return out
}
