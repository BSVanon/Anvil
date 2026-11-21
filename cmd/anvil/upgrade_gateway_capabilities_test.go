package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGatewayFixture lays out a config file + systemd unit under dir,
// exactly as deployGatewayNode would have (but using plain renderUnit,
// not renderGatewayUnit — standing in for a gateway unit installed
// before the capability directives existed), and returns the unit's
// path. Both files use renderUnit's own fixed node-a.toml naming, so the
// unit's ExecStart= -config path and the file actually written agree
// without any string surgery.
func writeGatewayFixture(t *testing.T, dir, service string) string {
	t.Helper()
	configPath := filepath.Join(dir, "node-a.toml")
	config := renderGatewayConfig("a", dir, dir, "gateway.example.org", "", nil)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(dir, service+".service")
	unit := renderUnit("a", dir, dir, "/opt/anvil")
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}
	return unitPath
}

// writeStandardFixture is writeGatewayFixture's standard-mode
// counterpart: a config with no [node] mode line at all. publicURL is a
// fixed dummy value so renderConfig never falls into its own
// auto-detect-public-IP path (a real network call this test must not
// make) — the same reason TestRenderConfigGolden_StandardUnchanged
// (deploy_gateway_test.go) always passes one too.
func writeStandardFixture(t *testing.T, dir, service string) string {
	t.Helper()
	configPath := filepath.Join(dir, "node-a.toml")
	config := renderConfig("a", dir, "", "", "http://203.0.113.5:9333", dir)
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(dir, service+".service")
	unit := renderUnit("a", dir, dir, "/opt/anvil")
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}
	return unitPath
}

// TestEnsureGatewayCapabilities_AddsToGatewayUnit is the required
// upgrade test: a gateway unit predating this feature gets both
// capability directives.
func TestEnsureGatewayCapabilities_AddsToGatewayUnit(t *testing.T) {
	dir := t.TempDir()
	unitPath := writeGatewayFixture(t, dir, "anvil-a")

	added := ensureGatewayCapabilitiesIn(dir)
	if added != 1 {
		t.Fatalf("ensureGatewayCapabilitiesIn modified %d unit(s), want 1", added)
	}

	got, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{gatewayCapabilityAmbient, gatewayCapabilityBoundingSet} {
		if !strings.Contains(string(got), want) {
			t.Errorf("unit after upgrade is missing %q:\n%s", want, got)
		}
	}
}

// TestEnsureGatewayCapabilities_SkipsStandardUnit confirms a
// standard-mode node's unit is left untouched: it has no [node]
// mode = "gateway" for any peer gateway's capability directives to make
// sense on.
func TestEnsureGatewayCapabilities_SkipsStandardUnit(t *testing.T) {
	dir := t.TempDir()
	unitPath := writeStandardFixture(t, dir, "anvil-a")
	before, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}

	added := ensureGatewayCapabilitiesIn(dir)
	if added != 0 {
		t.Fatalf("ensureGatewayCapabilitiesIn modified %d unit(s), want 0 for a standard-mode node", added)
	}

	after, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("a standard-mode unit changed")
	}
}

// TestEnsureGatewayCapabilities_Idempotent confirms a gateway unit that
// already has both directives (a fresh deploy via renderGatewayUnit, or
// a unit this function already patched once) is reported as unmodified
// on a second pass, and its bytes don't change.
func TestEnsureGatewayCapabilities_Idempotent(t *testing.T) {
	dir := t.TempDir()
	unitPath := writeGatewayFixture(t, dir, "anvil-a")

	if added := ensureGatewayCapabilitiesIn(dir); added != 1 {
		t.Fatalf("first pass modified %d unit(s), want 1", added)
	}
	afterFirst, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}

	if added := ensureGatewayCapabilitiesIn(dir); added != 0 {
		t.Fatalf("second pass modified %d unit(s), want 0 (already present)", added)
	}
	afterSecond, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterFirst) != string(afterSecond) {
		t.Error("a second pass changed an already-patched unit")
	}
}

// TestEnsureGatewayCapabilities_SkipsUnrelatedUnits mirrors
// ensureExecStartPreHookIn's own "unrelated unit" guard: a
// anvil-*.service file that doesn't invoke our binary is never touched,
// however it's shaped.
func TestEnsureGatewayCapabilities_SkipsUnrelatedUnits(t *testing.T) {
	dir := t.TempDir()
	unitPath := filepath.Join(dir, "anvil-unrelated.service")
	content := "[Service]\nExecStart=/usr/bin/some-other-program\n"
	if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	if added := ensureGatewayCapabilitiesIn(dir); added != 0 {
		t.Fatalf("ensureGatewayCapabilitiesIn modified %d unrelated unit(s), want 0", added)
	}
	got, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Error("an unrelated unit changed")
	}
}

// TestConfigDeclaresGatewayMode exercises the lightweight [node] mode
// scan directly, including the case a full-config fixture can't reach:
// a mode line that exists but outside the [node] table.
func TestConfigDeclaresGatewayMode(t *testing.T) {
	cases := map[string]bool{
		"[node]\nmode = \"gateway\"\n":  true,
		"[node]\nmode = \"standard\"\n": false,
		"[node]\nname = \"x\"\n":        false,
		"":                              false,
		"[other]\nmode = \"gateway\"\n": false,
		"[other]\nmode = \"gateway\"\n[node]\nname=\"x\"\n": false,
	}
	for input, want := range cases {
		if got := configDeclaresGatewayMode(input); got != want {
			t.Errorf("configDeclaresGatewayMode(%q) = %v, want %v", input, got, want)
		}
	}
}
