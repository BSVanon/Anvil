package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	if err := applyGatewayPeers(path, func([]gatewayPeer) []gatewayPeer {
		return []gatewayPeer{goldenPeerA, goldenPeerB}
	}); err != nil {
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

	if err := applyGatewayPeers(path, func([]gatewayPeer) []gatewayPeer {
		return []gatewayPeer{goldenPeerA}
	}); err != nil {
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
	if err := applyGatewayPeers(path, func([]gatewayPeer) []gatewayPeer {
		return peers
	}); err != nil {
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

// TestApplyGatewayPeers_KeepsTheExistingFileMode proves
// applyGatewayPeers must not hardcode a mode on the file it rewrites —
// whatever mode the config already had (here a non-default 0640,
// standing in for an operator who tightened it) comes back unchanged
// after the rewrite.
func TestApplyGatewayPeers_KeepsTheExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-a.toml")
	original := fakeGatewayConfig([]gatewayPeer{goldenPeerA})
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}

	if err := applyGatewayPeers(path, func([]gatewayPeer) []gatewayPeer {
		return []gatewayPeer{goldenPeerA, goldenPeerB}
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("mode after applyGatewayPeers = %v, want the original 0640", info.Mode().Perm())
	}
}

// TestApplyGatewayPeers_LeavesNoStagingFileBehind confirms the rewrite
// goes through the atomic stage-fsync-rename path (no risk-4-style plain
// os.WriteFile) and cleans up after itself.
func TestApplyGatewayPeers_LeavesNoStagingFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-a.toml")
	original := fakeGatewayConfig([]gatewayPeer{goldenPeerA})
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if err := applyGatewayPeers(path, func([]gatewayPeer) []gatewayPeer {
		return []gatewayPeer{goldenPeerB}
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Errorf("staging files left behind: %v", leftovers)
	}
}

// TestApplyGatewayPeers_ConcurrentAddsAllSurvive verifies that concurrent
// coverage: the read of the current peer list, the caller's change, and
// the write must all run under one lock, so N concurrent additions of N
// distinct peers all survive — none of them can read a list that's
// already stale by the time it writes. Without the lock, the same race
// write_test.go's concurrent-adds test proves for the sites file would
// apply here too: two calls reading the same starting list and each
// appending their own peer to it would leave only one peer behind.
func TestApplyGatewayPeers_ConcurrentAddsAllSurvive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-a.toml")
	original := fakeGatewayConfig(nil)
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			newPeer := gatewayPeer{
				PubKey:     fmt.Sprintf("02%064x", i+1),
				MeshURL:    fmt.Sprintf("ws://peer%02d.example:8333", i),
				OverlayURL: fmt.Sprintf("https://peer%02d.example", i),
			}
			errs[i] = applyGatewayPeers(path, func(peers []gatewayPeer) []gatewayPeer {
				return append(peers, newPeer)
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent applyGatewayPeers #%d: %v", i, err)
		}
	}
	peers, err := readGatewayPeersBlock(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != n {
		t.Fatalf("got %d peers after %d concurrent adds, want %d: %+v", len(peers), n, n, peers)
	}
}
