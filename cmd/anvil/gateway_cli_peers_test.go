package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTomlSectionHeader(t *testing.T) {
	cases := map[string]struct {
		name string
		ok   bool
	}{
		"[mesh]":             {"mesh", true},
		"[overlay]":          {"overlay", true},
		"[api.app_payments]": {"api.app_payments", true},
		"[[peers]]":          {"", false},
		"seeds = []":         {"", false},
		"":                   {"", false},
		"[]":                 {"", false},
	}
	for line, want := range cases {
		name, ok := tomlSectionHeader(line)
		if ok != want.ok || (ok && name != want.name) {
			t.Errorf("tomlSectionHeader(%q) = %q, %v; want %q, %v", line, name, ok, want.name, want.ok)
		}
	}
}

func TestReplaceGatewayPeerField(t *testing.T) {
	peers := []gatewayPeer{goldenPeerA, goldenPeerB}

	cases := []struct {
		section, trimmed string
		wantOK           bool
		wantContains     string
	}{
		{"mesh", "seeds = []", true, "wss://peer-a.example:8333"},
		{"mesh", "allowed_peers = []", true, goldenPeerA.PubKey},
		{"overlay", "named_peers = []", true, "https://peer-a.example"},
		{"bsv", "header_fallback_peers = []", true, "https://peer-b.example"},
		{"node", "name = \"x\"", false, ""},
		{"mesh", "seeds", false, ""}, // no "=" — not a key/value line
		{"api", "seeds = []", false, ""},
	}
	for _, c := range cases {
		got, ok := replaceGatewayPeerField(c.section, c.trimmed, peers)
		if ok != c.wantOK {
			t.Errorf("replaceGatewayPeerField(%q, %q) ok = %v, want %v", c.section, c.trimmed, ok, c.wantOK)
			continue
		}
		if ok && !strings.Contains(got, c.wantContains) {
			t.Errorf("replaceGatewayPeerField(%q, %q) = %q, want it to contain %q", c.section, c.trimmed, got, c.wantContains)
		}
	}
}

func TestReadGatewayPeersBlock(t *testing.T) {
	dir := t.TempDir()

	t.Run("no marked block at all", func(t *testing.T) {
		path := filepath.Join(dir, "no-block.toml")
		if err := os.WriteFile(path, []byte("[node]\nname = \"x\"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		peers, err := readGatewayPeersBlock(path)
		if err != nil || len(peers) != 0 {
			t.Errorf("readGatewayPeersBlock(no block) = %v, %v; want empty, nil", peers, err)
		}
	})

	t.Run("empty block", func(t *testing.T) {
		path := filepath.Join(dir, "empty-block.toml")
		content := "[node]\nname = \"x\"\n\n" + gatewayPeersBeginMarker + "\n" + gatewayPeersEndMarker + "\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		peers, err := readGatewayPeersBlock(path)
		if err != nil || len(peers) != 0 {
			t.Errorf("readGatewayPeersBlock(empty block) = %v, %v; want empty, nil", peers, err)
		}
	})

	t.Run("two peers round-trip through renderGatewayPeersBlock", func(t *testing.T) {
		path := filepath.Join(dir, "two-peers.toml")
		content := "[node]\nname = \"x\"\n\n" + renderGatewayPeersBlock([]gatewayPeer{goldenPeerA, goldenPeerB}) + "\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		peers, err := readGatewayPeersBlock(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(peers) != 2 || peers[0] != goldenPeerA || peers[1] != goldenPeerB {
			t.Errorf("readGatewayPeersBlock round-trip mismatch: got %+v", peers)
		}
	})

	t.Run("a commented line outside the markers is not a peer", func(t *testing.T) {
		path := filepath.Join(dir, "outside-marker.toml")
		content := "# " + goldenPeerA.PubKey + "@" + goldenPeerA.MeshURL + "@" + goldenPeerA.OverlayURL + "\n" +
			gatewayPeersBeginMarker + "\n" + gatewayPeersEndMarker + "\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		peers, err := readGatewayPeersBlock(path)
		if err != nil || len(peers) != 0 {
			t.Errorf("readGatewayPeersBlock picked up a peer line outside the markers: %+v, %v", peers, err)
		}
	})
}

// fakeGatewayConfig builds a minimal but structurally complete gateway
// config (as deployGatewayNode would write it) with some deliberately
// unrelated, hand-added content interspersed, so
// TestApplyGatewayPeers_PreservesUnrelatedContent can prove
// applyGatewayPeers never touches anything it doesn't own.
func fakeGatewayConfig(peers []gatewayPeer) string {
	return `# hand note: this gateway serves our internal tools only
[node]
name = "my-gateway"
data_dir = "/var/lib/anvil"
listen = "0.0.0.0:8333"
api_listen = "0.0.0.0:9333"
mode = "gateway"

[mesh]
seeds = ` + tomlStringArray(peerMeshURLs(peers)) + `
allowed_peers = ` + tomlStringArray(peerPubKeys(peers)) + `

[bsv]
nodes = ["seed.bitcoinsv.io:8333"]
header_fallback_peers = ` + tomlStringArray(peerOverlayURLs(peers)) + `

[overlay]
enabled = true
named_peers = ` + tomlStringArray(peerOverlayURLs(peers)) + `

[gateway]
enabled = true
api_host = "gateway.example.org"
sites_file = "/etc/anvil/gateway-sites.conf"
# a hand-added comment the operator left here

[api]
trust_proxy = false
payment_satoshis = 0

` + renderGatewayPeersBlock(peers) + `
`
}

func TestApplyGatewayPeers_PreservesUnrelatedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-a.toml")
	original := fakeGatewayConfig([]gatewayPeer{goldenPeerA})
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if err := applyGatewayPeers(path, []gatewayPeer{goldenPeerA, goldenPeerB}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)

	unrelated := []string{
		"# hand note: this gateway serves our internal tools only",
		`name = "my-gateway"`,
		`data_dir = "/var/lib/anvil"`,
		`listen = "0.0.0.0:8333"`,
		`api_listen = "0.0.0.0:9333"`,
		`mode = "gateway"`,
		`nodes = ["seed.bitcoinsv.io:8333"]`,
		`enabled = true`,
		`api_host = "gateway.example.org"`,
		`sites_file = "/etc/anvil/gateway-sites.conf"`,
		"# a hand-added comment the operator left here",
		`trust_proxy = false`,
		`payment_satoshis = 0`,
	}
	for _, line := range unrelated {
		if !strings.Contains(got, line) {
			t.Errorf("applyGatewayPeers lost unrelated line %q\nfull output:\n%s", line, got)
		}
	}

	wantFields := []string{
		`seeds = ["wss://peer-a.example:8333", "ws://10.0.0.2:8333"]`,
		`allowed_peers = ["` + goldenPeerA.PubKey + `", "` + goldenPeerB.PubKey + `"]`,
		`header_fallback_peers = ["https://peer-a.example", "https://peer-b.example"]`,
		`named_peers = ["https://peer-a.example", "https://peer-b.example"]`,
	}
	for _, line := range wantFields {
		if !strings.Contains(got, line) {
			t.Errorf("applyGatewayPeers did not update field to %q\nfull output:\n%s", line, got)
		}
	}

	peers, err := readGatewayPeersBlock(path)
	if err != nil {
		t.Fatalf("unexpected error re-reading peers block: %v", err)
	}
	if len(peers) != 2 || peers[0] != goldenPeerA || peers[1] != goldenPeerB {
		t.Errorf("marked block after applyGatewayPeers = %+v, want [goldenPeerA, goldenPeerB]", peers)
	}
}

func TestApplyGatewayPeers_RemovingAPeerClearsItEverywhere(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-a.toml")
	original := fakeGatewayConfig([]gatewayPeer{goldenPeerA, goldenPeerB})
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if err := applyGatewayPeers(path, []gatewayPeer{goldenPeerA}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if strings.Contains(got, goldenPeerB.PubKey) {
		t.Errorf("applyGatewayPeers left peer B's pubkey behind after removal:\n%s", got)
	}
	if strings.Contains(got, goldenPeerB.OverlayURL) {
		t.Errorf("applyGatewayPeers left peer B's overlay url behind after removal:\n%s", got)
	}
}

// TestGatewayPeerAdd_ReplacesByPubKey exercises the "add" path's dedup
// rule directly against readGatewayPeersBlock/applyGatewayPeers (not
// through gatewayPeerAdd itself, which calls restartGatewayService and
// would try to restart a real systemd unit): adding a peer whose pubkey
// already exists must update that entry in place, not append a
// duplicate.
func TestGatewayPeerAdd_ReplacesByPubKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-a.toml")
	original := fakeGatewayConfig([]gatewayPeer{goldenPeerA})
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	peers, err := readGatewayPeersBlock(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := gatewayPeer{PubKey: goldenPeerA.PubKey, MeshURL: "wss://peer-a-new.example:8333", OverlayURL: "https://peer-a-new.example"}
	replaced := false
	for i, p := range peers {
		if p.PubKey == updated.PubKey {
			peers[i] = updated
			replaced = true
			break
		}
	}
	if !replaced {
		peers = append(peers, updated)
	}
	if err := applyGatewayPeers(path, peers); err != nil {
		t.Fatal(err)
	}

	final, err := readGatewayPeersBlock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != 1 || final[0] != updated {
		t.Errorf("expected the single peer to be replaced in place, got %+v", final)
	}
}
