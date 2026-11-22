package main

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BSVanon/Anvil/internal/config"
)

// gatewayPeer is one entry of ANVIL_GATEWAY_PEERS / `anvil gateway peer add`:
// another gateway this node federates with directly, bypassing the public
// mesh and overlay discovery entirely so the two stay a closed network.
type gatewayPeer struct {
	PubKey     string // hex identity public key, lowercased
	MeshURL    string // ws:// or wss:// — goes into [mesh] seeds
	OverlayURL string // https:// (or loopback http://, for dev) — goes into [overlay] named_peers and [bsv] header_fallback_peers
}

// parseGatewayPeers parses ANVIL_GATEWAY_PEERS /
// `--gateway-peers`: "<pubkey>@<mesh-ws-url>@<overlay-https-url>[,...]".
// An empty string is not an error — a gateway may start with no peers,
// even from a non-interactive install, and add them later via
// `anvil gateway peer add`.
func parseGatewayPeers(raw string) ([]gatewayPeer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var peers []gatewayPeer
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, "@")
		if len(parts) != 3 {
			return nil, fmt.Errorf(`invalid peer entry %q: want "<pubkey>@<mesh-ws-url>@<overlay-https-url>"`, entry)
		}
		pubKey, err := validateGatewayPeerPubKey(parts[0])
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", entry, err)
		}
		meshURL, err := validateGatewayPeerURL(parts[1], "ws", "wss")
		if err != nil {
			return nil, fmt.Errorf("peer %q: mesh url: %w", entry, err)
		}
		overlayURL, err := validateGatewayOverlayURL(parts[2])
		if err != nil {
			return nil, fmt.Errorf("peer %q: overlay url: %w", entry, err)
		}
		peers = append(peers, gatewayPeer{PubKey: pubKey, MeshURL: meshURL, OverlayURL: overlayURL})
	}
	return peers, nil
}

// validateGatewayPeerPubKey requires a lowercase-normalised, 33-byte
// compressed EC public key in hex (66 characters, leading byte 0x02 or
// 0x03) — the same form this codebase derives everywhere else (e.g.
// cmd/anvil/deploy.go's generateWIF, cmd/anvil/info.go's identityHex).
func validateGatewayPeerPubKey(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	b, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("pubkey %q is not valid hex: %w", raw, err)
	}
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return "", fmt.Errorf("pubkey %q is not a 33-byte compressed public key", raw)
	}
	return raw, nil
}

// validateGatewayPeerURL requires raw to parse as an absolute URL with a
// non-empty host and one of the given schemes.
func validateGatewayPeerURL(raw string, schemes ...string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a valid URL", raw)
	}
	for _, s := range schemes {
		if u.Scheme == s {
			return raw, nil
		}
	}
	return "", fmt.Errorf("%q must use scheme %s", raw, strings.Join(schemes, " or "))
}

// validateGatewayOverlayURL applies the exact trust rule
// internal/config.FilterTrustedHeaderPeers enforces at runtime for
// [bsv] header_fallback_peers (https, or loopback http for local/dev) —
// reused rather than re-implemented so a peer URL this command accepts is
// guaranteed to also be accepted when the node consults it as a header
// fallback source.
func validateGatewayOverlayURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	valid, rejected := config.FilterTrustedHeaderPeers([]string{raw})
	if len(rejected) > 0 || len(valid) == 0 {
		return "", fmt.Errorf("%q must be an https URL (or a loopback http URL for local/dev)", raw)
	}
	return raw, nil
}

func peerMeshURLs(peers []gatewayPeer) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.MeshURL)
	}
	return out
}

func peerPubKeys(peers []gatewayPeer) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.PubKey)
	}
	return out
}

func peerOverlayURLs(peers []gatewayPeer) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.OverlayURL)
	}
	return out
}

// gatewayPeersBeginMarker / gatewayPeersEndMarker bound the human-readable
// peer registry `anvil gateway peer add|remove` edits in place (see
// cmd/anvil/gateway_cli_peers.go). deploy writes the same block so the
// two code paths never drift on format.
const (
	gatewayPeersBeginMarker = "# BEGIN gateway peers"
	gatewayPeersEndMarker   = "# END gateway peers"
)

// renderGatewayPeersBlock renders the marked comment block deploy and
// `anvil gateway peer` both read and write: one commented
// "pubkey@mesh-url@overlay-url" line per peer, so the raw peer list
// survives round-tripping even though [mesh] seeds / allowed_peers,
// [overlay] named_peers and [bsv] header_fallback_peers only carry the
// derived, per-field values (a pubkey has no field of its own in
// [overlay]/[bsv], and a mesh url has none in [bsv]/[overlay] — the
// marked block is the one place all three fields of a peer stay together).
func renderGatewayPeersBlock(peers []gatewayPeer) string {
	var b strings.Builder
	b.WriteString(gatewayPeersBeginMarker + "\n")
	for _, p := range peers {
		fmt.Fprintf(&b, "# %s@%s@%s\n", p.PubKey, p.MeshURL, p.OverlayURL)
	}
	b.WriteString(gatewayPeersEndMarker)
	return b.String()
}

// renderGatewayConfig renders a gateway node's anvil.toml:
//
//   - [node] mode = "gateway", and no public_url (no IP auto-detection —
//     a closed gateway should not register a public address);
//   - [mesh] seeds / allowed_peers and [overlay] named_peers and
//     [bsv] header_fallback_peers derived from peers;
//   - [gateway] enabled, api_host, sites_file;
//   - [api] trust_proxy = false, payment_satoshis = 0.
//
// apiHost must be non-empty — internal/config.Load fails a gateway-enabled
// config with no resolvable api_host, and this command never sets
// public_url for it to fall back to, so deployGatewayNode checks this
// before ever calling renderGatewayConfig.
func renderGatewayConfig(node, dataDir, configDir, apiHost, nodeName string, args gatewayDeployArgs) string {
	meshPort := "8333"
	apiPort := "9333"
	if node == "b" {
		meshPort = "8334"
		apiPort = "9334"
	}

	name := nodeName
	if name == "" {
		name = autoNodeName(node, configDir)
	}

	// internal/config.finalizeGateway defaults an unset sites_file to
	// exactly this path; written out explicitly so an operator reading
	// the file sees the real path rather than an implicit default.
	sitesFile := filepath.Join(configDir, "gateway-sites.conf")
	acmeConfig := ""
	if args.ACMEAcceptTOS {
		acmeConfig += "acme_accept_tos = true\n"
	}
	if args.ACMEEmail != "" {
		acmeConfig += fmt.Sprintf("acme_email = \"%s\"\n", tomlEscapeString(args.ACMEEmail))
	}

	return fmt.Sprintf(`# Anvil Node %s (gateway)
[node]
name = "%s"
data_dir = "%s"
listen = "0.0.0.0:%s"
api_listen = "0.0.0.0:%s"
mode = "gateway"

[mesh]
seeds = %s
allowed_peers = %s

[bsv]
nodes = ["seed.bitcoinsv.io:8333", "seed.satoshisvision.network:8333"]
header_fallback_peers = %s

[arc]
enabled = true
url = "https://arc.gorillapool.io"

[junglebus]
enabled = true
url = "junglebus.gorillapool.io"

[overlay]
enabled = true
topics = ["anvil:mainnet"]
named_peers = %s

[envelopes]
max_ephemeral_ttl = 3600
max_durable_size = 65536

[messaging]
# Gateway deployments limit the operator API token to this node's own identity box.
operator_reads_all_boxes = false

[gateway]
enabled = true
api_host = "%s"
sites_file = "%s"
%s
[api]
explorer_origin = "ce15872085966376ffe4479ecf32d88fc6be026aed0246054bf7bfaab2ea756a_0"
rate_limit = 100
payment_satoshis = 0
trust_proxy = false

[api.app_payments]
allow_passthrough = true
allow_split = true
allow_token_gating = true
max_app_price_sats = 10000

%s
`, strings.ToUpper(node), tomlEscapeString(name), tomlEscapeString(dataDir), meshPort, apiPort,
		tomlStringArray(peerMeshURLs(args.Peers)), tomlStringArray(peerPubKeys(args.Peers)),
		tomlStringArray(peerOverlayURLs(args.Peers)), tomlStringArray(peerOverlayURLs(args.Peers)),
		tomlEscapeString(apiHost), tomlEscapeString(sitesFile), acmeConfig, renderGatewayPeersBlock(args.Peers))
}

// deployAnyNode dispatches to deployNode or deployGatewayNode by mode, so
// cmdDeploy's per-node loop stays a single call regardless of mode.
func deployAnyNode(mode, node, configDir, dataDir, installDir, seedPeer, nodeName, publicURL, apiHost string, args gatewayDeployArgs, dryRun bool) {
	if mode == "gateway" {
		deployGatewayNode(node, configDir, dataDir, installDir, apiHost, args, nodeName, dryRun)
		return
	}
	deployNode(node, configDir, dataDir, installDir, seedPeer, nodeName, publicURL, dryRun)
}

// gatewayCapabilityAmbient and gatewayCapabilityBoundingSet are the two
// systemd directives a gateway unit needs to bind 80 and 443 without
// running as root. Matched and inserted as exact, whole lines by both
// renderGatewayUnit (a fresh deploy) and ensureGatewayCapabilitiesIn
// (upgrade_gateway_capabilities.go, for a unit that predates this), so
// the two paths can never disagree about what "present" means.
const (
	gatewayCapabilityAmbient      = "AmbientCapabilities=CAP_NET_BIND_SERVICE"
	gatewayCapabilityBoundingSet  = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
	gatewayCapabilityInsertAnchor = "LimitNOFILE=65536"
	// gatewayCapabilityInsertBlock is what goes right after one, exact
	// occurrence of gatewayCapabilityInsertAnchor — see
	// insertAfterAnchorOnce (upgrade_gateway_capabilities.go), the one
	// place both renderGatewayUnit and ensureGatewayCapabilitiesIn do the
	// actual insert, so the two paths can never disagree about where or
	// how.
	gatewayCapabilityInsertBlock = "\n\n# Bind 80/443 without running as root.\n" +
		gatewayCapabilityAmbient + "\n" + gatewayCapabilityBoundingSet
)

// renderGatewayUnit is renderUnit's gateway-mode counterpart: the exact
// same unit, with the two capability directives inserted right after the
// LimitNOFILE line, so the process can bind 80 and 443 while still
// running as the unprivileged "anvil" user (the rest of the unit's
// hardening — ProtectSystem=strict and friends — is otherwise identical
// for both modes). A standard-mode node keeps calling renderUnit
// directly and is byte-for-byte unaffected.
//
// Errors only if renderUnit's own template ever stops containing exactly
// one LimitNOFILE line — a template bug, not an operator or runtime
// condition — rather than silently installing a gateway unit that can
// never bind 80 or 443 as the unprivileged "anvil" user.
func renderGatewayUnit(node, configDir, dataDir, installDir string) (string, error) {
	unit := renderUnit(node, configDir, dataDir, installDir)
	withCapabilities, ok := insertAfterAnchorOnce(unit, gatewayCapabilityInsertAnchor, gatewayCapabilityInsertBlock)
	if !ok {
		return "", fmt.Errorf("gateway unit template: %q anchor not found exactly once", gatewayCapabilityInsertAnchor)
	}
	return withCapabilities, nil
}

// deployGatewayNode is deployNode's gateway-mode counterpart: the same
// "never overwrite an existing config" guard, writing
// renderGatewayConfig's template instead of renderConfig's, and
// renderGatewayUnit instead of renderUnit for the one systemd directive
// pair gateway mode needs that a standard node doesn't.
func deployGatewayNode(node, configDir, dataDir, installDir, apiHost string, args gatewayDeployArgs, nodeName string, dryRun bool) {
	unitContent, err := renderGatewayUnit(node, configDir, dataDir, installDir)
	if err != nil {
		fatal(err.Error())
	}
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName(node))
	if dryRun {
		fmt.Printf("  [dry-run] would write %s\n", unitPath)
	} else {
		if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
			fatal("write systemd unit: " + err.Error())
		}
		fmt.Printf("  wrote %s\n", unitPath)
	}

	tomlPath := filepath.Join(configDir, fmt.Sprintf("node-%s.toml", node))
	writeGatewayConfigIfMissing(tomlPath, node, dataDir, configDir, apiHost, nodeName, args, dryRun)

	chownRecursive(dataDir, "anvil")
}

// writeGatewayConfigIfMissing is deployGatewayNode's config-writing step,
// pulled out on its own (the same split upgrade.go's
// ensureExecStartPreHook/ensureExecStartPreHookIn already uses) so it can
// be exercised directly in a test with dryRun=false — deployGatewayNode
// itself always also writes a systemd unit under /etc/systemd/system,
// which needs root.
func writeGatewayConfigIfMissing(tomlPath, node, dataDir, configDir, apiHost, nodeName string, args gatewayDeployArgs, dryRun bool) {
	if _, err := os.Stat(tomlPath); os.IsNotExist(err) {
		tomlContent := renderGatewayConfig(node, dataDir, configDir, apiHost, nodeName, args)
		if dryRun {
			fmt.Printf("  [dry-run] would write %s (gateway)\n", tomlPath)
		} else {
			if err := os.WriteFile(tomlPath, []byte(tomlContent), 0644); err != nil {
				fatal("write config file: " + err.Error())
			}
			fmt.Printf("  wrote %s (gateway)\n", tomlPath)
		}
	} else {
		fmt.Printf("  %s exists — not overwriting\n", tomlPath)
	}
}
