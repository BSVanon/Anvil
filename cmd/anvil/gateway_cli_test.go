package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// writeGatewayTestConfig renders a valid gateway config (the same
// template deploy writes, proven byte-exact by
// TestRenderGatewayConfigGolden_TwoPeers) to dir/node-a.toml, optionally
// with an identity WIF appended, and returns its path.
func writeGatewayTestConfig(t *testing.T, dir, apiHost, wif string) string {
	t.Helper()
	content := renderGatewayConfig("a", filepath.Join(dir, "data"), dir, apiHost, "test-gateway", []gatewayPeer{goldenPeerA})
	if wif != "" {
		content += fmt.Sprintf("\n[identity]\nwif = %q\n", wif)
	}
	path := filepath.Join(dir, "node-a.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadGatewayConfigOrFatal_Success(t *testing.T) {
	dir := t.TempDir()
	path := writeGatewayTestConfig(t, dir, "gateway-a.example.org", "")

	cfg := loadGatewayConfigOrFatal(path)
	if !cfg.Gateway.Enabled {
		t.Error("loaded config has Gateway.Enabled = false, want true")
	}
	if cfg.Gateway.APIHost != "gateway-a.example.org" {
		t.Errorf("Gateway.APIHost = %q, want gateway-a.example.org", cfg.Gateway.APIHost)
	}
}

func TestCmdGatewayInfo(t *testing.T) {
	dir := t.TempDir()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wif := key.Wif()
	wantIdentity := fmt.Sprintf("%x", key.PubKey().Compressed())

	path := writeGatewayTestConfig(t, dir, "gateway-a.example.org", wif)

	out := captureStdout(t, func() {
		cmdGatewayInfo([]string{"-config", path})
	})

	if !strings.Contains(out, "Identity:     "+wantIdentity) {
		t.Errorf("expected identity %q in output:\n%s", wantIdentity, out)
	}
	if !strings.Contains(out, "API host:     gateway-a.example.org") {
		t.Errorf("expected api_host in output:\n%s", out)
	}
	if !strings.Contains(out, "Mesh URL:     ws://gateway-a.example.org:8333") {
		t.Errorf("expected a ws:// mesh URL on the mesh listen port, got:\n%s", out)
	}
	if !strings.Contains(out, "Overlay URL:  https://gateway-a.example.org") {
		t.Errorf("expected an https:// overlay URL, got:\n%s", out)
	}
	wantPeerAddLine := fmt.Sprintf("sudo anvil gateway peer add %s ws://gateway-a.example.org:8333 https://gateway-a.example.org", wantIdentity)
	if !strings.Contains(out, wantPeerAddLine) {
		t.Errorf("expected the suggested peer add line %q in output:\n%s", wantPeerAddLine, out)
	}
}

func TestPrintGatewayUsageMentionsAllSubcommands(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	printGatewayUsage()
	os.Stderr = oldStderr
	_ = w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	out := string(buf[:n])

	for _, want := range []string{"site add", "site remove", "site list", "peer add", "peer remove", "peer list", "info"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage text missing %q:\n%s", want, out)
		}
	}
}
