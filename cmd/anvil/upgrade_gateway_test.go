package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/sitesfile"
)

// TestUpgradeFileHandling_LeavesGatewayConfigAndSitesFileUntouched runs
// cmdUpgrade's actual local, in-process file-handling step —
// ensureExecStartPreHookIn — against a temporary gateway install (a real
// anvil.toml, a real sites file, and a real systemd unit, laid out the
// same way deployGatewayNode produces them) and checks the real
// before/after file contents.
//
// cmdUpgrade itself can't run end-to-end in a unit test (it downloads a
// release over the network, shells out to systemctl, and calls
// assertRoot). Of everything it does locally, only ensureExecStartPreHook
// touches a file that isn't the anvil binary or its symlink — the
// binary install path, the backup/staging files and the symlink all live
// under -install-dir/ and /usr/local/bin, never under the config
// directory. This test exercises that one real function against a real
// fixture, rather than asking an AST walk to prove a negative about every
// other call in the file: a walk can only ever rule out the exact call
// shapes it knows to look for (plain, unqualified calls to 11 hardcoded
// names), where this proves the actual outcome on disk.
func TestUpgradeFileHandling_LeavesGatewayConfigAndSitesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "etc")
	dataDir := filepath.Join(dir, "var")
	systemdDir := filepath.Join(dir, "systemd")
	for _, d := range []string{configDir, dataDir, systemdDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// A real gateway config and a real sites file, exactly as
	// deployGatewayNode would have written them.
	configPath := filepath.Join(configDir, "node-a.toml")
	configContent := renderGatewayConfig("a", dataDir, configDir, "gateway-a.example.org", "golden-gateway", []gatewayPeer{goldenPeerA})
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}
	sitesPath := filepath.Join(configDir, "gateway-sites.conf")
	if err := sitesfile.Add(sitesPath, sitesfile.Entry{Kind: "domain", Value: "served.example.com"}, "gateway-a.example.org"); err != nil {
		t.Fatal(err)
	}

	// An old-style unit (pre-v2.2.0: no ExecStartPre self-heal hook yet) —
	// the exact shape ensureExecStartPreHookIn exists to backfill, so
	// running it against this fixture actually does something, rather
	// than finding the hook already present and taking its no-op path.
	unitPath := filepath.Join(systemdDir, "anvil-a.service")
	unitContent := renderUnit("a", configDir, dataDir, "/opt/anvil")
	unitContent = strings.Replace(unitContent, "ExecStartPre=/opt/anvil/anvil doctor --locks-only\n", "", 1)
	if err := os.WriteFile(unitPath, []byte(unitContent), 0644); err != nil {
		t.Fatal(err)
	}

	configBefore, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	sitesBefore, err := os.ReadFile(sitesPath)
	if err != nil {
		t.Fatal(err)
	}

	added := ensureExecStartPreHookIn(systemdDir)
	if added != 1 {
		t.Fatalf("ensureExecStartPreHookIn modified %d unit(s), want 1 (the fixture unit starts with no hook)", added)
	}

	configAfter, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	sitesAfter, err := os.ReadFile(sitesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configBefore, configAfter) {
		t.Errorf("the gateway config changed after upgrade's file-handling step.\nbefore:\n%s\nafter:\n%s", configBefore, configAfter)
	}
	if !bytes.Equal(sitesBefore, sitesAfter) {
		t.Errorf("the sites file changed after upgrade's file-handling step.\nbefore:\n%s\nafter:\n%s", sitesBefore, sitesAfter)
	}

	// The unit still points at the same gateway config, and that config
	// still declares gateway mode — upgrade's unit edit (adding the hook
	// line) doesn't disturb the node's gateway-ness or its pairing with
	// this config file.
	unitAfter, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unitAfter), "-config "+configPath) {
		t.Errorf("the unit no longer references the same config path:\n%s", unitAfter)
	}
	if !strings.Contains(string(configAfter), `mode = "gateway"`) {
		t.Errorf("the config no longer declares gateway mode:\n%s", configAfter)
	}
}
