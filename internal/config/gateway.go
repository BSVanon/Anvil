package config

import "fmt"

// GatewayConfig configures gateway mode: serving a publisher's own domain
// whose content lives entirely on-chain, resolved through the ORDFS
// custom-domain convention (a DNS TXT record naming a 1Sat origin). See
// internal/gateway for the mechanism this drives; this struct only carries
// the operator-facing settings — B8 (version tracking) and B9 (TLS) read
// these same fields rather than adding their own copies.
type GatewayConfig struct {
	// Enabled turns gateway serving on. Off (the default) is a standard
	// node: byte-for-byte today's behaviour — no Router is even
	// constructed, and the sites file is never read.
	Enabled bool `toml:"enabled"`

	// APIHost is the Host header that reaches this node's own API once
	// gateway mode is on. Left empty, every Host that isn't a configured
	// site reaches the API — today's behaviour on the existing :9333
	// listener, where local tools, mesh peers and tests send all kinds of
	// Host headers and must keep reaching it. B9 sets this to a specific
	// admin hostname when it mounts the same router on 443/80, so those
	// public ports don't default-expose the API to an arbitrary Host.
	APIHost string `toml:"api_host"`

	// SitesFile is the allowlist of domains and/or origins this gateway
	// serves (internal/gateway's Allowlist). Unset defaults, in Load, to
	// "gateway-sites.conf" next to this node's own config file.
	SitesFile string `toml:"sites_file"`

	// TXTCacheTTL is how long a positive _ordfs TXT answer is cached, in
	// seconds. 0 or unset → default 300 (5m).
	TXTCacheTTL int `toml:"txt_cache_ttl"`

	// TXTStaleGrace is how long a site keeps serving its last good TXT
	// answer after the resolver starts erroring, in seconds. 0 or unset →
	// default 86400 (24h).
	TXTStaleGrace int `toml:"txt_stale_grace"`

	// RootMaxAge is the Cache-Control max-age, in seconds, for a site's
	// "/" — short, because the answer changes on every publisher update.
	// 0 or unset → default 60.
	RootMaxAge int `toml:"root_max_age"`

	// ContentScope is "site" (the default — internal/gateway's reference-
	// reachability check) or "any" (today's unrestricted /content/
	// behaviour). Anything else is treated as "site": an unrecognised
	// value fails safe to the stricter default rather than the open one.
	ContentScope string `toml:"content_scope"`
}

const (
	defaultGatewayTXTCacheTTL   = 300   // 5m
	defaultGatewayTXTStaleGrace = 86400 // 24h
	defaultGatewayRootMaxAge    = 60
	defaultGatewayContentScope  = "site"
)

// validateNodeMode rejects anything but [node] mode's two recognised
// values (empty counts as "standard"). See NodeConfig.Mode's doc comment
// for why nothing else in this package, or in internal/gateway, branches
// on the value itself.
func validateNodeMode(mode string) error {
	switch mode {
	case "", "standard", "gateway":
		return nil
	default:
		return fmt.Errorf(`invalid [node] mode %q: must be "standard" or "gateway"`, mode)
	}
}
