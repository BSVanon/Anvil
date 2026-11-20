package main

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/sitesfile"
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
func renderGatewayConfig(node, dataDir, configDir, apiHost, nodeName string, peers []gatewayPeer) string {
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

[gateway]
enabled = true
api_host = "%s"
sites_file = "%s"

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
		tomlStringArray(peerMeshURLs(peers)), tomlStringArray(peerPubKeys(peers)),
		tomlStringArray(peerOverlayURLs(peers)), tomlStringArray(peerOverlayURLs(peers)),
		tomlEscapeString(apiHost), tomlEscapeString(sitesFile), renderGatewayPeersBlock(peers))
}

// validateGatewayDeployMode is resolveGatewayDeployArgs's pure check on
// --mode alone, split out so it returns an error instead of calling
// fatal — dropping this check is then a real, test-asserted regression
// rather than something only a manual CLI run would catch.
func validateGatewayDeployMode(mode string) error {
	if mode != "standard" && mode != "gateway" {
		return fmt.Errorf("--mode must be standard or gateway")
	}
	return nil
}

// validateGatewayDeployAPIHost is resolveGatewayDeployArgs's pure check
// on --api-host: required in gateway mode (there is no [node] public_url
// for internal/config.Load to default it from — gateway mode never sets
// one), and shaped like a hostname — the same rule
// internal/sitesfile.ValidateDomain applies to a site domain, so IP
// literals and anything but ASCII LDH labels are refused here too. In
// standard mode apiHost is unused, so nothing is checked.
func validateGatewayDeployAPIHost(mode, apiHost string) error {
	if mode != "gateway" {
		return nil
	}
	if apiHost == "" {
		return fmt.Errorf("--mode gateway requires --api-host (there is no [node] public_url for internal/config.Load to default it from — gateway mode never sets one)")
	}
	if _, ok := sitesfile.ValidateDomain(apiHost); !ok {
		return fmt.Errorf("--api-host %q is not a valid hostname: no IP literals, ASCII LDH labels only", apiHost)
	}
	return nil
}

// resolveGatewayDeployArgs validates `anvil deploy`'s gateway-mode flags
// and parses --gateway-peers, failing fast with a clear message rather
// than writing a config internal/config.Load would only reject once the
// daemon tries to start. Kept here (not cmd/anvil/deploy.go) so deploy.go
// only grows by the one line that calls this.
func resolveGatewayDeployArgs(mode, apiHost, gatewayPeersRaw string) []gatewayPeer {
	if err := validateGatewayDeployMode(mode); err != nil {
		fatal(err.Error())
	}
	peers, err := parseGatewayPeers(gatewayPeersRaw)
	if err != nil {
		fatal("--gateway-peers: " + err.Error())
	}
	if err := validateGatewayDeployAPIHost(mode, apiHost); err != nil {
		fatal(err.Error())
	}
	return peers
}

// deployAnyNode dispatches to deployNode or deployGatewayNode by mode, so
// cmdDeploy's per-node loop stays a single call regardless of mode.
func deployAnyNode(mode, node, configDir, dataDir, installDir, seedPeer, nodeName, publicURL, apiHost string, peers []gatewayPeer, dryRun bool) {
	if mode == "gateway" {
		deployGatewayNode(node, configDir, dataDir, installDir, apiHost, peers, nodeName, dryRun)
		return
	}
	deployNode(node, configDir, dataDir, installDir, seedPeer, nodeName, publicURL, dryRun)
}

// deployGatewayNode is deployNode's gateway-mode counterpart: same
// systemd unit template (renderUnit, unchanged — a gateway node is still
// "anvil -config <path>", nothing about the unit itself differs) and the
// same "never overwrite an existing config" guard, writing
// renderGatewayConfig's template instead of renderConfig's.
func deployGatewayNode(node, configDir, dataDir, installDir, apiHost string, peers []gatewayPeer, nodeName string, dryRun bool) {
	unitContent := renderUnit(node, configDir, dataDir, installDir)
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
	writeGatewayConfigIfMissing(tomlPath, node, dataDir, configDir, apiHost, nodeName, peers, dryRun)

	chownRecursive(dataDir, "anvil")
}

// writeGatewayConfigIfMissing is deployGatewayNode's config-writing step,
// pulled out on its own (the same split upgrade.go's
// ensureExecStartPreHook/ensureExecStartPreHookIn already uses) so it can
// be exercised directly in a test with dryRun=false — deployGatewayNode
// itself always also writes a systemd unit under /etc/systemd/system,
// which needs root.
func writeGatewayConfigIfMissing(tomlPath, node, dataDir, configDir, apiHost, nodeName string, peers []gatewayPeer, dryRun bool) {
	if _, err := os.Stat(tomlPath); os.IsNotExist(err) {
		tomlContent := renderGatewayConfig(node, dataDir, configDir, apiHost, nodeName, peers)
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
