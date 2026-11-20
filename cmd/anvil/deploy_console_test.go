package main

import (
	"os"
	"strings"
	"testing"
)

// TestCmdDeployGolden_StandardModeConsoleOutput pins cmdDeploy's console
// output for a standard-mode dry run, captured from the pre-gateway
// binary's own behaviour and normalised (every path that varies by
// machine or run — the config/data/install directories and this
// process's own binary path — is replaced by a fixed placeholder before
// comparing). A standard install must look exactly as it did before
// gateway mode existed; this is the test that would have caught the
// mode line printing unconditionally.
func TestCmdDeployGolden_StandardModeConsoleOutput(t *testing.T) {
	dir := t.TempDir()
	configDir := dir + "/etc"
	dataDir := dir + "/var"
	installDir := dir + "/opt"
	for _, d := range []string{configDir, dataDir, installDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	args := []string{
		"--dry-run", "--nodes", "a", "--skip-health",
		"--config-dir", configDir, "--data-dir", dataDir, "--install-dir", installDir,
		"--name", "golden-node", "--public-url", "http://203.0.113.5:9333",
	}
	out := captureStdout(t, func() { cmdDeploy(args) })

	norm := out
	norm = strings.ReplaceAll(norm, selfBin, "<SELFBIN>")
	norm = strings.ReplaceAll(norm, configDir, "<CONFIGDIR>")
	norm = strings.ReplaceAll(norm, dataDir, "<DATADIR>")
	norm = strings.ReplaceAll(norm, installDir, "<INSTALLDIR>")

	want := `=== Anvil Deploy ===
  nodes:       [a]
  config-dir:  <CONFIGDIR>
  data-dir:    <DATADIR>
  install-dir: <INSTALLDIR>
  dry-run:     true


[→] Pre-flight: checking environment
  [dry-run] would create user anvil
  [dry-run] would create <DATADIR>/anvil/headers
  [dry-run] would create <DATADIR>/anvil/envelopes
  [dry-run] would create <DATADIR>/anvil/overlay
  [dry-run] would create <DATADIR>/anvil/wallet
  [dry-run] would create <DATADIR>/anvil/invoices
  [dry-run] would create <DATADIR>/anvil/proofs
  [dry-run] would create <DATADIR>/anvil/mesh
  [dry-run] would create <CONFIGDIR>/node-a.env with generated WIF
  ✓ Pre-flight passed

[→] Installing binary
  [dry-run] would copy <SELFBIN> → <INSTALLDIR>/anvil

[→] Deploying Node A
  [dry-run] would write /etc/systemd/system/anvil-a.service
  [dry-run] would write <CONFIGDIR>/node-a.toml

=== Dry run complete — no changes made ===
`
	if norm != want {
		t.Errorf("standard-mode deploy console output changed from the pre-gateway binary's behaviour (paths normalised).\ngot:\n%s\nwant:\n%s", norm, want)
	}
}

// TestCmdDeployGolden_GatewayModeShowsModeLine is the mode-line's other
// half: gateway mode must show it, so the line's presence actually
// tracks the mode rather than always being off.
func TestCmdDeployGolden_GatewayModeShowsModeLine(t *testing.T) {
	dir := t.TempDir()
	configDir := dir + "/etc"
	dataDir := dir + "/var"
	installDir := dir + "/opt"
	for _, d := range []string{configDir, dataDir, installDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	args := []string{
		"--dry-run", "--nodes", "a", "--skip-health",
		"--config-dir", configDir, "--data-dir", dataDir, "--install-dir", installDir,
		"--name", "golden-gateway", "--mode", "gateway", "--api-host", "gateway.example.org",
	}
	out := captureStdout(t, func() { cmdDeploy(args) })
	if !strings.Contains(out, "\n  mode:        gateway\n") {
		t.Errorf("expected gateway mode to print its mode line, got:\n%s", out)
	}
}
