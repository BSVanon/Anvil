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
	config := renderGatewayConfig("a", dir, dir, "gateway.example.org", "", gatewayDeployArgs{})
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

// TestEnsureGatewayCapabilities_SkipsStandardUnit confirms a node with
// the gateway off is left untouched: it has no [gateway] enabled = true
// for any capability directive to make sense on.
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

// TestConfigDeclaresGatewayEnabled exercises the real-TOML-parse
// [gateway] enabled check directly, including the case a full-config
// fixture can't reach: an enabled line that exists but outside the
// [gateway] table, and [node] mode set to "gateway" with [gateway]
// enabled left unset or false — confirming detection really does key on
// the field gateway_wire.go's wireGateway itself reads, not [node] mode.
// Also covers the two false-positive shapes a prefix/substring line scan
// got wrong (a commented-out "true" on the same line, and an unrelated
// key merely starting with "enabled") and the two spellings a real TOML
// parser must treat alike (a trailing comment, and no space around "=").
func TestConfigDeclaresGatewayEnabled(t *testing.T) {
	cases := map[string]bool{
		"[gateway]\nenabled = true\n":   true,
		"[gateway]\nenabled = false\n":  false,
		"[gateway]\napi_host = \"x\"\n": false,
		"":                              false,
		"[other]\nenabled = true\n":     false,
		"[other]\nenabled = true\n[gateway]\napi_host=\"x\"\n": false,
		// [node] mode = "gateway" alone, with no [gateway] table at all,
		// must NOT be detected — this is the exact case the old,
		// [node]-mode-keyed check got wrong.
		"[node]\nmode = \"gateway\"\n": false,
		// The inverse: [gateway] enabled = true with [node] mode left as
		// "standard" MUST be detected — the hand-edited-config case.
		"[node]\nmode = \"standard\"\n\n[gateway]\nenabled = true\n": true,
		// A "true" mentioned only in a trailing comment must never flip
		// this on — the exact false positive a substring match produced.
		"[gateway]\nenabled = false  # flip to true once DNS is ready\n": false,
		// A key that merely starts with "enabled" is not the field — the
		// exact false positive a prefix match produced.
		"[gateway]\nenabled_metrics = true\n": false,
		// A real TOML parser tolerates a trailing comment and missing
		// whitespace around "=" the same way; both must still detect.
		"[gateway]\nenabled = true # comment\n": true,
		"[gateway]\nenabled=true\n":             true,
	}
	for input, want := range cases {
		if got := configDeclaresGatewayEnabled(input); got != want {
			t.Errorf("configDeclaresGatewayEnabled(%q) = %v, want %v", input, got, want)
		}
	}
}

// TestEnsureGatewayCapabilities_DetectsByGatewayEnabledNotNodeMode is the
// required hand-edited-config case, exercised through the full
// ensureGatewayCapabilitiesIn path (not just the lightweight scan
// above): [gateway] enabled = true with [node] mode left at "standard"
// still gets the capability. The runtime binds 80 and 443 purely on
// [gateway] enabled (gateway_wire.go's wireGateway) — [node] mode is an
// operator-facing label this check must never depend on.
func TestEnsureGatewayCapabilities_DetectsByGatewayEnabledNotNodeMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "node-a.toml")
	config := "[node]\nmode = \"standard\"\n\n[gateway]\nenabled = true\n"
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(dir, "anvil-a.service")
	unit := renderUnit("a", dir, dir, "/opt/anvil")
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}

	added := ensureGatewayCapabilitiesIn(dir)
	if added != 1 {
		t.Fatalf("ensureGatewayCapabilitiesIn modified %d unit(s), want 1 for [gateway] enabled=true with [node] mode=standard", added)
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

// TestEnsureGatewayCapabilities_MissingAnchorIsReportedAndLeftAlone
// confirms a unit shaped unexpectedly — no LimitNOFILE=65536 line at
// all — is never guessed at: left byte-for-byte unchanged, and the skip
// is reported rather than silent.
func TestEnsureGatewayCapabilities_MissingAnchorIsReportedAndLeftAlone(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "node-a.toml")
	config := renderGatewayConfig("a", dir, dir, "gateway.example.org", "", gatewayDeployArgs{})
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatal(err)
	}
	unit := strings.Replace(renderUnit("a", dir, dir, "/opt/anvil"), gatewayCapabilityInsertAnchor+"\n", "", 1)
	if strings.Contains(unit, gatewayCapabilityInsertAnchor) {
		t.Fatal("test setup: fixture still contains the anchor")
	}
	unitPath := filepath.Join(dir, "anvil-a.service")
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}

	var added int
	out := captureStdout(t, func() { added = ensureGatewayCapabilitiesIn(dir) })
	if added != 0 {
		t.Fatalf("ensureGatewayCapabilitiesIn modified %d unit(s), want 0 when the anchor is missing", added)
	}
	got, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != unit {
		t.Error("a unit with a missing anchor changed")
	}
	if !strings.Contains(out, "anchor not found") {
		t.Errorf("expected the missing-anchor skip to be reported, got:\n%s", out)
	}
}

// TestInsertAfterAnchorOnce exercises the shared insert helper directly,
// decoupled from any unit-file fixture: exactly one anchor inserts,
// anything else — zero, or more than one — leaves text unchanged and
// reports false.
func TestInsertAfterAnchorOnce(t *testing.T) {
	cases := []struct {
		name string
		text string
		ok   bool
		want string
	}{
		{"exactly once", "a\nANCHOR\nb\n", true, "a\nANCHOR-INSERTED\nb\n"},
		{"missing", "a\nb\n", false, "a\nb\n"},
		{"duplicated", "ANCHOR\nANCHOR\n", false, "ANCHOR\nANCHOR\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := insertAfterAnchorOnce(c.text, "ANCHOR", "-INSERTED")
			if ok != c.ok {
				t.Errorf("ok = %v, want %v", ok, c.ok)
			}
			if got != c.want {
				t.Errorf("result = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEnsureGatewayCapabilities_InsertsOnlyTheMissingLine confirms a unit
// that already has exactly one of the two capability lines — a
// hand-edited unit, or one a previous, interrupted upgrade only
// partially patched — gets only the other line added: never a second
// copy of the line it already has.
func TestEnsureGatewayCapabilities_InsertsOnlyTheMissingLine(t *testing.T) {
	cases := []struct {
		name    string
		already string
	}{
		{"has only AmbientCapabilities", gatewayCapabilityAmbient},
		{"has only CapabilityBoundingSet", gatewayCapabilityBoundingSet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "node-a.toml")
			config := renderGatewayConfig("a", dir, dir, "gateway.example.org", "", gatewayDeployArgs{})
			if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
				t.Fatal(err)
			}
			base := renderUnit("a", dir, dir, "/opt/anvil")
			unit := strings.Replace(base, gatewayCapabilityInsertAnchor, gatewayCapabilityInsertAnchor+"\n"+c.already, 1)
			unitPath := filepath.Join(dir, "anvil-a.service")
			if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
				t.Fatal(err)
			}

			added := ensureGatewayCapabilitiesIn(dir)
			if added != 1 {
				t.Fatalf("ensureGatewayCapabilitiesIn modified %d unit(s), want 1", added)
			}
			got, err := os.ReadFile(unitPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{gatewayCapabilityAmbient, gatewayCapabilityBoundingSet} {
				if n := strings.Count(string(got), want); n != 1 {
					t.Errorf("unit after upgrade contains %q %d time(s), want exactly 1:\n%s", want, n, got)
				}
			}
		})
	}
}
