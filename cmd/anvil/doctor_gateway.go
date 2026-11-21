package main

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
	"github.com/BSVanon/Anvil/internal/sitesfile"
)

// doctorGatewayChecks runs the gateway checks (the mode, whether the
// sites file parses, each listed domain's live TXT status, the TLS
// checks below, and the closed-network posture) and returns the number
// of genuine issues found — most findings here are warnings, not
// issues, since a gateway degrades gracefully in each case (it just
// serves nothing for that one domain, or stays open to more
// peers/addresses than a fully closed network would want, or can't
// issue a certificate until an operator sets one more config field). An
// unbound 80 or 443 is the one TLS finding that is a genuine issue: a
// gateway that can't be reached isn't serving anything at all.
//
// txtStatus is liveTXTStatus in production; tests inject a stub so this
// never makes a real DNS call. portBound is livePortBound in production;
// tests inject a stub so this never depends on a real bound socket.
// apiURL is the same `http://127.0.0.1:<APIListen>` cmdDoctor already
// built for every other live check.
func doctorGatewayChecks(cfg *config.Config, apiURL string, txtStatus func(ctx context.Context, domain string) string, portBound func(addr string) bool) int {
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

	issues += doctorGatewayTLSChecks(cfg, apiURL, entries, portBound)

	if cfg.Node.PublicURL != "" {
		warn("[node] public_url is set on a gateway node — this registers a public address; a closed gateway should leave it empty")
	}
	if len(cfg.Overlay.NamedPeers) == 0 {
		warn("[overlay] named_peers is empty — this node has no closed-network peer list configured")
	}
	if len(cfg.Mesh.AllowedPeers) == 0 {
		warn("[mesh] allowed_peers is empty — any peer that completes the handshake may connect, and ACME challenge replication stays off")
	}
	for _, p := range cfg.BSV.HeaderFallbackPeers {
		if config.IsDefaultHeaderFallbackPeer(p) {
			warn("a default public endpoint (%s) would be contacted for header fallback — set [overlay] named_peers, or header_fallback_disabled, to stop this", p)
			break
		}
	}
	return issues
}

// doctorGatewayTLSChecks covers this brick's own four checks: whether
// 80 and 443 are actually bound, whether acme_accept_tos is set, each
// listed domain's on-disk certificate state, and whether ACME challenge
// replication has a live peer to reach. entries is the sites file
// doctorGatewayChecks already parsed — reused here rather than read a
// second time. Returns how many of these are genuine issues: an unbound
// port is one; nothing else here is (a missing certificate or TOS
// agreement is self-healing once the operator fixes the config, and a
// gateway with no mesh peer connected right now may simply be between
// connections).
func doctorGatewayTLSChecks(cfg *config.Config, apiURL string, entries []sitesfile.Entry, portBound func(addr string) bool) int {
	issues := 0

	for _, l := range []struct{ label, addr string }{
		{"443", cfg.Gateway.HTTPSListen},
		{"80", cfg.Gateway.HTTPListen},
	} {
		if l.addr == "" {
			continue // unconfigured: finalizeGateway would have defaulted this on a real boot
		}
		if portBound(l.addr) {
			pass("gateway %s bound (%s)", l.label, l.addr)
		} else {
			fail("gateway %s not bound (%s) — the gateway can't be reached", l.label, l.addr)
			issues++
		}
	}

	if cfg.Gateway.AcceptTOS {
		pass("acme_accept_tos is set")
	} else {
		warn("acme_accept_tos is false — every certificate issuance attempt fails until this is set")
	}

	// Cert state is read straight off disk: doctor is a separate process
	// from the daemon that actually requests certificates, so this is
	// the only state available to it. Skipped with no data_dir
	// configured — a bare test fixture, never a real boot, since
	// internal/config always has one.
	if cfg.Node.DataDir != "" {
		cache := gateway.NewCache(filepath.Join(cfg.Node.DataDir, "acme"), nil, nil, nil, nil)
		for _, e := range entries {
			if e.Kind != "domain" {
				continue
			}
			state := cache.SiteCertState(context.Background(), e.Value)
			switch {
			case state.LastError != "":
				warn("%s: certificate error — %s", e.Value, state.LastError)
			case state.Present:
				pass("%s: certificate valid until %s", e.Value, state.NotAfter.UTC().Format(time.RFC3339))
			default:
				warn("%s: no certificate issued yet", e.Value)
			}
		}
	}

	if len(cfg.Mesh.AllowedPeers) > 0 {
		if meshResp := httpGet(apiURL + "/mesh/status"); meshResp != nil {
			if mesh, ok := meshResp["mesh"].(map[string]interface{}); ok {
				if peerCount, ok := mesh["peers"].(float64); ok && int(peerCount) > 0 {
					pass("ACME challenge replication possible: %d allowed peer(s) connected", int(peerCount))
				} else {
					warn("ACME challenge replication configured but no mesh peer is connected right now")
				}
			}
		}
	}

	return issues
}

// livePortBound reports whether something accepts a TCP connection on
// addr's port, dialed against the loopback address — the same
// 127.0.0.1-regardless-of-bind-interface convention cmdDoctor already
// uses for apiURL, since a process bound to ":443" or "0.0.0.0:443" is
// always also reachable on loopback.
func livePortBound(addr string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1"+normalizePort(addr), 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
