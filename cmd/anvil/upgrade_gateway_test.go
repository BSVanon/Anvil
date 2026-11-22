package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/sitesfile"
)

// forbiddenUpgradeCalls are every function in this package that renders
// or writes a node config or a gateway sites file, called as a plain,
// unqualified identifier. `anvil upgrade` must call none of them:
// upgrading a binary must never rewrite a gateway's configuration or
// its sites file.
var forbiddenUpgradeCalls = map[string]bool{
	"renderConfig":             true,
	"renderGatewayConfig":      true,
	"renderGatewayPeersBlock":  true,
	"deployNode":               true,
	"deployGatewayNode":        true,
	"deployAnyNode":            true,
	"resolveGatewayDeployArgs": true,
	"applyGatewayPeers":        true,
}

// forbiddenSitesfileCalls are internal/sitesfile's own writing
// functions (Read alone is harmless, these three are not), called as
// sitesfile.<name>(...) — a package-qualified selector, which
// forbiddenUpgradeCalls' plain-identifier check can't see. The sites
// file's reader/writer live in that package, outside this one, so this
// second map is what actually closes the invariant now.
var forbiddenSitesfileCalls = map[string]bool{
	"Add":             true,
	"Remove":          true,
	"AtomicWriteFile": true,
}

// TestUpgradeNeverRewritesGatewayConfigOrSites parses the upgrade command's
// production source files and walks every call expression structurally, rather
// than running cmdUpgrade end-to-end (which would need a real systemd
// and a real release to download). It catches a forbidden call added
// anywhere in those files, including in code paths
// TestUpgradeFileHandling_LeavesGatewayConfigAndSitesFileUntouched
// (below) can't reach without that same systemd/network dependency;
// that other test instead proves the actual on-disk outcome of the one
// function the upgrade command calls locally. Keeping both: this one is
// structural coverage of the command, that one is a real fixture's
// real before/after bytes for the one reachable path.
func TestUpgradeNeverRewritesGatewayConfigOrSites(t *testing.T) {
	fset := token.NewFileSet()
	paths, err := filepath.Glob("upgrade*.go")
	if err != nil {
		t.Fatalf("find upgrade source files: %v", err)
	}

	var hits []string
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if forbiddenUpgradeCalls[fun.Name] {
					hits = append(hits, fset.Position(call.Pos()).String()+": "+fun.Name+"(...)")
				}
			case *ast.SelectorExpr:
				if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name == "sitesfile" && forbiddenSitesfileCalls[fun.Sel.Name] {
					hits = append(hits, fset.Position(call.Pos()).String()+": sitesfile."+fun.Sel.Name+"(...)")
				}
			}
			return true
		})
	}

	if len(hits) > 0 {
		t.Errorf("upgrade command calls a config/sites-file-writing function — anvil upgrade must leave a gateway's config and sites file untouched:\n%s", strings.Join(hits, "\n"))
	}
}

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
// fixture and checks the real bytes; see
// TestUpgradeNeverRewritesGatewayConfigOrSites, above, for the
// structural half of this invariant.
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
	configContent := renderGatewayConfig("a", dataDir, configDir, "gateway-a.example.org", "golden-gateway", gatewayDeployArgs{Peers: []gatewayPeer{goldenPeerA}})
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
