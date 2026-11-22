package main

import (
	"context"
	"net"
	"os"
	"os/user"
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
	return doctorGatewayChecksWithAPI(cfg, apiURL, txtStatus, portBound, true)
}

func doctorGatewayChecksWithAPI(cfg *config.Config, apiURL string, txtStatus func(ctx context.Context, domain string) string, portBound func(addr string) bool, apiAvailable bool) int {
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

	issues += doctorGatewayTLSChecksWithAPI(cfg, apiURL, entries, portBound, apiAvailable)

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
	return doctorGatewayTLSChecksWithAPI(cfg, apiURL, entries, portBound, true)
}

func doctorGatewayTLSChecksWithAPI(cfg *config.Config, apiURL string, entries []sitesfile.Entry, portBound func(addr string) bool, apiAvailable bool) int {
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
	//
	// Read-only: this never calls gateway.NewCache (which would create
	// the directory, at whatever mode and owner doctor's own process
	// happens to run as — root, if invoked as "sudo anvil doctor" — a
	// directory the daemon, running as a different user, might then be
	// unable to write to). OpenCacheIfExists only ever reads.
	if cfg.Node.DataDir != "" {
		acmeDir := filepath.Join(cfg.Node.DataDir, "acme")
		cache, ok := gateway.OpenCacheIfExists(acmeDir)
		if !ok {
			pass("no certificates yet (%s does not exist)", acmeDir)
		} else {
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
			issues += doctorAcmeDirOwnershipAndMode(acmeDir)
		}
	}

	if len(cfg.Mesh.AllowedPeers) > 0 && apiAvailable {
		if meshResp := httpGet(apiURL + "/mesh/status"); meshResp != nil {
			if mesh, ok := meshResp["mesh"].(map[string]interface{}); ok {
				if peerCount, ok := mesh["peers"].(float64); ok && int(peerCount) > 0 {
					pass("ACME challenge replication possible: %d allowed peer(s) connected", int(peerCount))
				} else {
					warn("ACME challenge replication configured but no mesh peer is connected right now")
				}
			}
		}
	} else if len(cfg.Mesh.AllowedPeers) > 0 {
		skip("ACME challenge replication status: API not answering")
	}

	return issues
}

// doctorAcmeDirOwnershipAndMode checks dir's owner and mode once it's
// already known to exist (see doctorGatewayTLSChecks — this is never
// called when the directory is absent; OpenCacheIfExists reports that
// case on its own, and there is nothing to check ownership of yet).
//
// The owner must be the daemon user, "anvil" — looked up the same way
// internal/sitesfile's own owner-tracking code does (user.Lookup by
// name, via cmd/anvil/deploy.go's ensureUser), skipping the check
// entirely where there's no such user at all, such as a developer's
// workstation that never runs the real daemon user. The mode must be
// 0700, the same mode gateway.NewCache itself creates a fresh directory
// with.
//
// Report-only: doctorGatewayChecks and doctorGatewayTLSChecks take no
// --yes/fix parameter today (unlike cmdDoctor's own separate
// runSelfHealingChecks path), and adding one here would mean rewriting
// every existing call site across this package's test files for a
// single new check. A wrong owner or mode is reported as a FAIL with
// the one-line fix to run by hand, the same way an unbound port is
// reported without doctor binding it itself.
func doctorAcmeDirOwnershipAndMode(dir string) int {
	issues := 0

	info, err := os.Stat(dir)
	if err != nil {
		// Already confirmed to exist by the caller a moment ago; a
		// failure here (removed concurrently, a permissions change) is
		// outside what this check can usefully diagnose.
		return issues
	}

	if mode := info.Mode().Perm(); mode != 0700 {
		fail("%s mode is %04o, want 0700 — run: chmod 0700 %s", dir, mode, dir)
		issues++
	}

	if _, err := user.Lookup("anvil"); err == nil {
		if owner := fileOwner(dir); owner != "" && owner != "anvil" {
			fail("%s owned by %q, want \"anvil\" — run: chown anvil %s", dir, owner, dir)
			issues++
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
