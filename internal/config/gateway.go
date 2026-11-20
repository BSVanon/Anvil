package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

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
	// gateway mode is on (D1). Left unset, Load resolves it from [node]
	// public_url's host — overlay federation calls this node at
	// public_url, so the two must agree, and a gateway node that sets
	// only public_url (not api_host) gets a working default for free. If
	// [gateway] is enabled and neither is set, Load fails: D1's Router has
	// no wildcard any more (an empty APIHost reaches only a loopback
	// Host, never an arbitrary one), so a gateway with no api_host at all
	// would be unreachable at its own API. If both are set and their
	// hosts disagree, Load also fails, since federation would 404 against
	// whichever one Router isn't using. See finalizeGateway.
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

	// ContentScope is "" (defaults to "site"), "site" (internal/gateway's
	// reference-reachability check) or "any" (today's unrestricted
	// /content/ behaviour) — decision 6, tightened by D3: Load rejects
	// anything else outright rather than silently falling back to "site".
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

// finalizeGateway is the one call Load makes for every gateway-related
// default and validation (B3): [node] mode (validateNodeMode),
// GatewayConfig's own numeric/path defaults, D3's strict content_scope
// check, and D2's api_host resolution and its two overlap rules with the
// sites file. configPath is Load's own config-file path, needed for
// SitesFile's "next to this node's own config file" default.
func finalizeGateway(cfg *Config, configPath string) error {
	if err := validateNodeMode(cfg.Node.Mode); err != nil {
		return err
	}

	if cfg.Gateway.TXTCacheTTL <= 0 {
		cfg.Gateway.TXTCacheTTL = defaultGatewayTXTCacheTTL
	}
	if cfg.Gateway.TXTStaleGrace <= 0 {
		cfg.Gateway.TXTStaleGrace = defaultGatewayTXTStaleGrace
	}
	if cfg.Gateway.RootMaxAge <= 0 {
		cfg.Gateway.RootMaxAge = defaultGatewayRootMaxAge
	}
	switch cfg.Gateway.ContentScope {
	case "":
		cfg.Gateway.ContentScope = defaultGatewayContentScope
	case "site", "any":
		// explicit and valid
	default:
		return fmt.Errorf(`invalid [gateway] content_scope %q: must be "" (defaults to "site"), "site" or "any"`, cfg.Gateway.ContentScope)
	}
	if cfg.Gateway.SitesFile == "" {
		// "the config dir" (decision 7) is wherever this node's own config
		// file lives, whatever it's named — not a hardcoded path — so a
		// gateway's sites file always sits next to its anvil.toml.
		cfg.Gateway.SitesFile = filepath.Join(filepath.Dir(configPath), "gateway-sites.conf")
	}

	// D2: api_host is resolved from, and reconciled against, [node]
	// public_url. With the gateway off, none of this can stop the node
	// from starting (fix cycle 2, item 1): a disagreeing api_host/
	// public_url and an api_host that happens to also be listed in the
	// sites file are both only real problems once the gateway is
	// actually serving anything — the same reasoning the "both empty"
	// check below already applied.
	apiHost := strings.TrimSpace(cfg.Gateway.APIHost)
	publicHost := urlHost(cfg.Node.PublicURL)
	switch {
	case apiHost == "":
		apiHost = publicHost
	case cfg.Gateway.Enabled && publicHost != "" && !strings.EqualFold(apiHost, publicHost):
		return fmt.Errorf("[gateway] api_host %q and [node] public_url's host %q disagree: overlay federation calls this node at public_url, so a mismatch would 404 it", apiHost, publicHost)
	}
	if apiHost == "" && cfg.Gateway.Enabled {
		return fmt.Errorf("[gateway] api_host is required when [gateway] enabled is true, and could not be defaulted from an empty [node] public_url")
	}
	cfg.Gateway.APIHost = apiHost

	if cfg.Gateway.Enabled && apiHost != "" && sitesFileListsDomain(cfg.Gateway.SitesFile, apiHost) {
		return fmt.Errorf("[gateway] api_host %q must not also be listed as a site in the sites file (%s): the API always wins, so a conflicting domain entry there is refused", apiHost, cfg.Gateway.SitesFile)
	}

	return nil
}

// urlHost extracts the hostname from a URL string such as
// "https://anvil.sendbsv.com", or "" if raw is empty or unparseable.
func urlHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Hostname()
}

// sitesFileListsDomain reports whether path's sites file, if present and
// readable, lists domain (case-insensitively, ignoring one trailing dot —
// the same normalisation internal/gateway's own validateDomain and
// normalizeHost apply) as a "domain" entry. A missing or unreadable file
// reports false — this overlap check only refuses a config it can
// affirmatively see conflicts in; a malformed sites file is
// internal/gateway's own concern at runtime (Allowlist logs and keeps the
// last good snapshot). This package deliberately doesn't import
// internal/gateway for its full parser: the only thing Load needs here is
// this one literal-match check, not sites-file validation.
func sitesFileListsDomain(path, domain string) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	want := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if want == "" {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "domain") {
			continue
		}
		got := strings.TrimSuffix(strings.ToLower(fields[1]), ".")
		if got == want {
			return true
		}
	}
	return false
}
