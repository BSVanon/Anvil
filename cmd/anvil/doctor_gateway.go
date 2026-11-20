package main

import (
	"context"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/sitesfile"
)

// doctorGatewayChecks runs the gateway checks (the mode, whether the
// sites file parses, each listed domain's live TXT status, and the
// closed-network posture) and returns the number of genuine issues
// found — the closed-posture findings and a domain with no TXT mapping
// are warnings, not issues, since a gateway degrades gracefully in both
// cases (it just serves nothing for that one domain, or stays open to
// more peers/addresses than a fully closed network would want).
//
// txtStatus is liveTXTStatus in production; tests inject a stub so this
// never makes a real DNS call.
func doctorGatewayChecks(cfg *config.Config, txtStatus func(ctx context.Context, domain string) string) int {
	issues := 0

	mode := cfg.Node.Mode
	if mode == "" {
		mode = "standard"
	}
	pass("mode: %s", mode)

	if !cfg.Gateway.Enabled {
		pass("gateway disabled")
		return issues
	}

	entries, err := sitesfile.Read(cfg.Gateway.SitesFile)
	switch {
	case err != nil:
		fail("sites file %s: %v", cfg.Gateway.SitesFile, err)
		issues++
	case len(entries) == 0:
		pass("sites file %s: no sites configured yet", cfg.Gateway.SitesFile)
	default:
		pass("sites file %s: %d entries", cfg.Gateway.SitesFile, len(entries))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, e := range entries {
			if e.Kind != "domain" {
				continue
			}
			status := txtStatus(ctx, e.Value)
			if strings.HasPrefix(status, "ordfs=") {
				pass("%s: %s", e.Value, status)
			} else {
				warn("%s: %s — this domain 404s until its TXT record is fixed", e.Value, status)
			}
		}
	}

	if cfg.Node.PublicURL != "" {
		warn("[node] public_url is set on a gateway node — this registers a public address; a closed gateway should leave it empty")
	}
	if len(cfg.Overlay.NamedPeers) == 0 {
		warn("[overlay] named_peers is empty — this node has no closed-network peer list configured")
	}
	if len(cfg.Mesh.AllowedPeers) == 0 {
		warn("[mesh] allowed_peers is empty — any peer that completes the handshake may connect")
	}
	for _, p := range cfg.BSV.HeaderFallbackPeers {
		if config.IsDefaultHeaderFallbackPeer(p) {
			warn("a default public endpoint (%s) would be contacted for header fallback — set [overlay] named_peers, or header_fallback_disabled, to stop this", p)
			break
		}
	}
	return issues
}
