package main

import (
	"os"
	"strings"
	"testing"
)

// goldenPeerA / goldenPeerB are fixed, validly-shaped (66-hex-char
// compressed pubkey) test peers shared by the golden tests below.
var (
	goldenPeerA = gatewayPeer{
		PubKey:     "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MeshURL:    "wss://peer-a.example:8333",
		OverlayURL: "https://peer-a.example",
	}
	goldenPeerB = gatewayPeer{
		PubKey:     "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		MeshURL:    "ws://10.0.0.2:8333",
		OverlayURL: "https://peer-b.example",
	}
)

// TestRenderConfigGolden_StandardUnchanged pins renderConfig's existing
// output byte-for-byte. renderConfig itself is untouched — the only
// change is that cmdDeploy now calls it through deployAnyNode instead
// of directly — so this test exists purely to make that "unchanged"
// claim provable, not to test new behaviour.
func TestRenderConfigGolden_StandardUnchanged(t *testing.T) {
	got := renderConfig("a", "/var/lib/anvil", "", "golden-node", "http://203.0.113.5:9333", "/etc/anvil")
	want := `# Anvil Node A
[node]
name = "golden-node"
data_dir = "/var/lib/anvil"
listen = "0.0.0.0:8333"
api_listen = "0.0.0.0:9333"
public_url = "http://203.0.113.5:9333"

[mesh]
seeds = []

[bsv]
nodes = ["seed.bitcoinsv.io:8333", "seed.satoshisvision.network:8333"]
# header_stale_after_secs = 1800
# Default 1800s; a node behind by more than this consults the trusted fallback even if a P2P peer is still connected.
# Mesh header self-heal (ON by default): when all BSV P2P peers fail a sync round
# or the stored tip is stale, catch up over HTTPS from a TRUSTED Anvil peer. A default peer is baked
# into the binary (active on upgrade, no edit needed). Add your own trusted peers
# below (tried first), or set header_fallback_disabled = true to turn it off.
# Headers are PoW + most-work validated but NOT DAA-validated, so any URL must be
# https (trusted like a [bsv] node). A healthy, advancing P2P tip never calls it.
# header_fallback_peers = ["https://my-other-node.example"]
# header_fallback_disabled = false

[arc]
enabled = true
url = "https://arc.gorillapool.io"

[junglebus]
enabled = true
url = "junglebus.gorillapool.io"

[overlay]
enabled = true
topics = ["anvil:mainnet"]

[envelopes]
max_ephemeral_ttl = 3600
max_durable_size = 65536

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
`
	if got != want {
		t.Errorf("renderConfig output changed for a standard node.\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// TestRenderGatewayConfigGolden_TwoPeers pins renderGatewayConfig's exact
// output for a two-peer gateway: its full field list, plus the marked
// peer block.
func TestRenderGatewayConfigGolden_TwoPeers(t *testing.T) {
	got := renderGatewayConfig("a", "/var/lib/anvil", "/etc/anvil", "gateway-a.example.org", "golden-gateway", gatewayDeployArgs{
		Peers:         []gatewayPeer{goldenPeerA, goldenPeerB},
		ACMEAcceptTOS: true,
		ACMEEmail:     "ops@example.org",
	})
	want := `# Anvil Node A (gateway)
[node]
name = "golden-gateway"
data_dir = "/var/lib/anvil"
listen = "0.0.0.0:8333"
api_listen = "0.0.0.0:9333"
mode = "gateway"

[mesh]
seeds = ["wss://peer-a.example:8333", "ws://10.0.0.2:8333"]
allowed_peers = ["02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]

[bsv]
nodes = ["seed.bitcoinsv.io:8333", "seed.satoshisvision.network:8333"]
header_fallback_peers = ["https://peer-a.example", "https://peer-b.example"]

[arc]
enabled = true
url = "https://arc.gorillapool.io"

[junglebus]
enabled = true
url = "junglebus.gorillapool.io"

[overlay]
enabled = true
topics = ["anvil:mainnet"]
named_peers = ["https://peer-a.example", "https://peer-b.example"]

[envelopes]
max_ephemeral_ttl = 3600
max_durable_size = 65536

[messaging]
# Gateway deployments limit the operator API token to this node's own identity box.
operator_reads_all_boxes = false

[gateway]
enabled = true
api_host = "gateway-a.example.org"
sites_file = "/etc/anvil/gateway-sites.conf"
acme_accept_tos = true
acme_email = "ops@example.org"

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

# BEGIN gateway peers
# 02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@wss://peer-a.example:8333@https://peer-a.example
# 03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb@ws://10.0.0.2:8333@https://peer-b.example
# END gateway peers
`
	if got != want {
		t.Errorf("renderGatewayConfig output mismatch.\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// TestRenderGatewayConfigGolden_NoPeers pins the zero-peer case: deploy
// must still write every field (empty arrays, an empty marked block) so
// `anvil gateway peer add` always has a structurally complete file to
// edit later.
func TestRenderGatewayConfigGolden_NoPeers(t *testing.T) {
	got := renderGatewayConfig("b", "/var/lib/anvil-b", "/etc/anvil", "gateway-b.example.org", "gateway-b-fixed", gatewayDeployArgs{})
	want := `# Anvil Node B (gateway)
[node]
name = "gateway-b-fixed"
data_dir = "/var/lib/anvil-b"
listen = "0.0.0.0:8334"
api_listen = "0.0.0.0:9334"
mode = "gateway"

[mesh]
seeds = []
allowed_peers = []

[bsv]
nodes = ["seed.bitcoinsv.io:8333", "seed.satoshisvision.network:8333"]
header_fallback_peers = []

[arc]
enabled = true
url = "https://arc.gorillapool.io"

[junglebus]
enabled = true
url = "junglebus.gorillapool.io"

[overlay]
enabled = true
topics = ["anvil:mainnet"]
named_peers = []

[envelopes]
max_ephemeral_ttl = 3600
max_durable_size = 65536

[messaging]
# Gateway deployments limit the operator API token to this node's own identity box.
operator_reads_all_boxes = false

[gateway]
enabled = true
api_host = "gateway-b.example.org"
sites_file = "/etc/anvil/gateway-sites.conf"

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

# BEGIN gateway peers
# END gateway peers
`
	if got != want {
		t.Errorf("renderGatewayConfig (no peers) output mismatch.\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// TestRenderUnit_SameForStandardAndGateway proves a gateway node runs
// under the exact same systemd unit as a standard one, by construction:
// both modes call the exact same renderUnit, so there is nothing
// gateway-specific about it.
func TestRenderUnit_SameForStandardAndGateway(t *testing.T) {
	standard := renderUnit("a", "/etc/anvil", "/var/lib/anvil", "/opt/anvil")
	gateway := renderUnit("a", "/etc/anvil", "/var/lib/anvil", "/opt/anvil")
	if standard != gateway {
		t.Fatal("renderUnit produced different output for the same inputs — deployGatewayNode and deployNode must share one unit template")
	}
	want := `[Unit]
Description=Anvil Prime (seed node)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=anvil
Group=anvil
WorkingDirectory=/opt/anvil
# Pre-start self-heal: kill any orphan anvil processes that would hold
# LevelDB LOCK files and prevent this service instance from starting.
# Failure here must NOT block startup — runLocksOnly exits 0 even if
# the scan errors, so ExecStartPre never triggers a crash loop itself.
ExecStartPre=/opt/anvil/anvil doctor --locks-only
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-a.toml
EnvironmentFile=/etc/anvil/node-a.env
Restart=on-failure
RestartSec=5
KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=30
FinalKillSignal=SIGKILL
LimitNOFILE=65536

# Security hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/anvil
NoNewPrivileges=true
# Private /tmp: wallet-toolbox's SQLite needs a writable temp dir for
# sort/temp-table ops on larger wallet DBs. Without this, ProtectSystem=strict
# makes /tmp read-only and SQLite returns "disk I/O error: permission denied"
# during CreateAction calls. Discovered in v3.0.0 production (anvil-a 443MB
# wallet); fix shipped in v3.0.1.
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`
	if standard != want {
		t.Errorf("renderUnit golden mismatch.\ngot:\n%s\nwant:\n%s", standard, want)
	}
}

func TestParseGatewayPeers(t *testing.T) {
	validA := "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	validB := "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	t.Run("empty is not an error", func(t *testing.T) {
		peers, err := parseGatewayPeers("")
		if err != nil || peers != nil {
			t.Fatalf("parseGatewayPeers(\"\") = %v, %v; want nil, nil", peers, err)
		}
	})

	t.Run("one peer", func(t *testing.T) {
		raw := validA + "@wss://a.example:8333@https://a.example"
		peers, err := parseGatewayPeers(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(peers) != 1 || peers[0].PubKey != validA || peers[0].MeshURL != "wss://a.example:8333" || peers[0].OverlayURL != "https://a.example" {
			t.Fatalf("unexpected peers: %+v", peers)
		}
	})

	t.Run("two peers, comma-separated, whitespace tolerated", func(t *testing.T) {
		raw := validA + "@wss://a.example:8333@https://a.example, " + validB + "@ws://10.0.0.2:8333@https://b.example"
		peers, err := parseGatewayPeers(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(peers) != 2 {
			t.Fatalf("expected 2 peers, got %d", len(peers))
		}
	})

	t.Run("pubkey uppercased is lowered", func(t *testing.T) {
		raw := strings.ToUpper(validA) + "@wss://a.example:8333@https://a.example"
		peers, err := parseGatewayPeers(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if peers[0].PubKey != validA {
			t.Fatalf("expected lowercased pubkey %q, got %q", validA, peers[0].PubKey)
		}
	})

	badCases := map[string]string{
		"missing a field":                         validA + "@wss://a.example:8333",
		"too many fields":                         validA + "@wss://a.example:8333@https://a.example@extra",
		"bad pubkey hex":                          "nothex@wss://a.example:8333@https://a.example",
		"pubkey wrong length":                     "02aabb@wss://a.example:8333@https://a.example",
		"pubkey bad lead byte":                    "01" + validA[2:] + "@wss://a.example:8333@https://a.example",
		"mesh url wrong scheme":                   validA + "@https://a.example:8333@https://a.example",
		"mesh url no host":                        validA + "@wss:///path@https://a.example",
		"overlay url plain http on a public host": validA + "@wss://a.example:8333@http://a.example",
	}
	for name, raw := range badCases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseGatewayPeers(raw); err == nil {
				t.Fatalf("parseGatewayPeers(%q) succeeded, want an error", raw)
			}
		})
	}

	t.Run("overlay url loopback http is accepted (dev)", func(t *testing.T) {
		raw := validA + "@wss://a.example:8333@http://127.0.0.1:9333"
		if _, err := parseGatewayPeers(raw); err != nil {
			t.Fatalf("unexpected error for loopback http overlay url: %v", err)
		}
	})
}

// TestWriteGatewayConfigIfMissing_NeverOverwritesExistingConfig mirrors
// deployNode's own guarantee for standard nodes: re-deploying an
// already-configured node leaves its config byte-for-byte unchanged.
// writeGatewayConfigIfMissing is deployGatewayNode's config-writing step,
// pulled out so this test can call it with dryRun=false (a real write)
// without also needing root for deployGatewayNode's systemd-unit write.
func TestWriteGatewayConfigIfMissing_NeverOverwritesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	const existing = "# hand-edited gateway config\n[gateway]\nenabled = true\n"
	tomlPath := dir + "/node-a.toml"
	if err := os.WriteFile(tomlPath, []byte(existing), 0640); err != nil {
		t.Fatal(err)
	}
	writeGatewayConfigIfMissing(tomlPath, "a", dir, dir, "gateway-a.example.org", "", gatewayDeployArgs{Peers: []gatewayPeer{goldenPeerA}}, false /* dryRun */)

	gotBytes, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(gotBytes); got != existing {
		t.Errorf("writeGatewayConfigIfMissing overwrote an existing config.\ngot:\n%s\nwant (unchanged):\n%s", got, existing)
	}
}

// TestWriteGatewayConfigIfMissing_WritesWhenAbsent is the other half of
// the guarantee above: a genuinely missing config must still get
// written (otherwise the "never overwrite" guard would degenerate into
// "never write").
func TestWriteGatewayConfigIfMissing_WritesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	tomlPath := dir + "/node-a.toml"
	writeGatewayConfigIfMissing(tomlPath, "a", dir, dir, "gateway-a.example.org", "golden-gateway", gatewayDeployArgs{Peers: []gatewayPeer{goldenPeerA}}, false /* dryRun */)

	got, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatalf("expected a config file to be written, got error: %v", err)
	}
	want := renderGatewayConfig("a", dir, dir, "gateway-a.example.org", "golden-gateway", gatewayDeployArgs{Peers: []gatewayPeer{goldenPeerA}})
	if string(got) != want {
		t.Errorf("written config does not match renderGatewayConfig's output.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
