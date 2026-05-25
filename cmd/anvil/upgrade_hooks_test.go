package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withSystemdDir overrides the unit-file scan location for the duration
// of a single test. We don't ship a "override" var in production because
// /etc/systemd/system is the only sane default; tests reach in via
// runtime patching of the constant-ish path used in ensureExecStartPreHook.
//
// Implementation trick: ensureExecStartPreHook references systemdDir as a
// local const. Rather than exposing a setter, we exercise it by creating
// a /tmp sandbox and chrooting... nope, overkill. Instead, test behavior
// by giving it real /etc/systemd/system and — no, that would modify the
// test host's systemd. We need a safer approach.
//
// Correct approach: refactor ensureExecStartPreHook to accept the dir as
// an argument. See ensureExecStartPreHookIn below; that's the real
// implementation, and the exported zero-arg ensureExecStartPreHook is a
// thin wrapper using the hardcoded path. Tests exercise the *In variant.

// TestEnsureExecStartPreHook_AddsMissingHook verifies the hook is
// inserted immediately before the first ExecStart= line when missing.
func TestEnsureExecStartPreHook_AddsMissingHook(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "anvil-a.service")
	original := `[Unit]
Description=Anvil Node A

[Service]
Type=simple
User=anvil
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-a.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(unit, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	n := ensureExecStartPreHookIn(dir)
	if n != 1 {
		t.Errorf("expected 1 modified file, got %d", n)
	}

	got, _ := os.ReadFile(unit)
	wantHook := "ExecStartPre=/opt/anvil/anvil doctor --locks-only"
	if !strings.Contains(string(got), wantHook) {
		t.Errorf("ExecStartPre hook missing from updated unit:\n%s", got)
	}
	// Ordering matters — hook must be BEFORE ExecStart=
	hookIdx := strings.Index(string(got), wantHook)
	execIdx := strings.Index(string(got), "ExecStart=/opt/anvil/anvil")
	if hookIdx == -1 || execIdx == -1 || hookIdx > execIdx {
		t.Errorf("hook inserted in wrong order (hook=%d, exec=%d)\n%s", hookIdx, execIdx, got)
	}
}

// TestEnsureExecStartPreHook_RewritesLegacyHook verifies that a unit
// with the v2.2.x `--fix-locks-only` alias gets rewritten to the
// canonical `--locks-only` form during upgrade.
func TestEnsureExecStartPreHook_RewritesLegacyHook(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "anvil-a.service")
	original := `[Service]
ExecStartPre=/opt/anvil/anvil doctor --fix-locks-only
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-a.toml
`
	if err := os.WriteFile(unit, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	n := ensureExecStartPreHookIn(dir)
	if n != 1 {
		t.Errorf("expected 1 modified file, got %d", n)
	}
	got, _ := os.ReadFile(unit)
	if strings.Contains(string(got), "--fix-locks-only") {
		t.Errorf("legacy --fix-locks-only still present after rewrite:\n%s", got)
	}
	if !strings.Contains(string(got), "ExecStartPre=/opt/anvil/anvil doctor --locks-only") {
		t.Errorf("canonical --locks-only hook missing after rewrite:\n%s", got)
	}
}

// TestEnsureExecStartPreHook_IdempotentOnExistingHook verifies a unit
// that already has the canonical hook is not modified (counter stays 0).
func TestEnsureExecStartPreHook_IdempotentOnExistingHook(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "anvil-a.service")
	original := `[Service]
ExecStartPre=/opt/anvil/anvil doctor --locks-only
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-a.toml
`
	if err := os.WriteFile(unit, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(unit)

	n := ensureExecStartPreHookIn(dir)
	if n != 0 {
		t.Errorf("expected 0 modified (already hooked), got %d", n)
	}
	after, _ := os.ReadFile(unit)
	if string(before) != string(after) {
		t.Error("file was modified despite hook already present")
	}
}

// TestEnsureExecStartPreHook_SkipsUnrelatedUnits verifies that a unit
// file named anvil-*.service but which doesn't ExecStart our binary is
// left alone. Defends against blasting hooks into someone else's unit
// that happens to share our naming prefix.
func TestEnsureExecStartPreHook_SkipsUnrelatedUnits(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "anvil-unrelated.service")
	original := `[Service]
ExecStart=/usr/bin/some-other-binary
`
	if err := os.WriteFile(unit, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	n := ensureExecStartPreHookIn(dir)
	if n != 0 {
		t.Errorf("expected 0 modified (wrong binary), got %d", n)
	}
	got, _ := os.ReadFile(unit)
	if strings.Contains(string(got), "doctor --locks-only") {
		t.Error("hook leaked into unrelated unit file")
	}
}

// TestNeedsV3Migrate verifies the v2 → v3 boundary detector that
// gates the upgrade-time overlay-migrate hook.
func TestNeedsV3Migrate(t *testing.T) {
	cases := []struct {
		name       string
		current    string
		next       string
		wantMigrate bool
	}{
		{"v2.3.2 -> v3.0.0 fires", "2.3.2", "3.0.0", true},
		{"v2.3.2 -> v3.0.1 fires", "2.3.2", "3.0.1", true},
		{"v2.3.2 -> v3.1.0 fires", "2.3.2", "3.1.0", true},
		{"v2.0.0 -> v3.0.0 fires", "2.0.0", "3.0.0", true},
		{"v1.5.0 -> v3.0.0 fires", "1.5.0", "3.0.0", true},
		{"v3.0.0 -> v3.0.1 skips (within v3)", "3.0.0", "3.0.1", false},
		{"v3.0.0 -> v3.1.0 skips (within v3)", "3.0.0", "3.1.0", false},
		{"v3.1.0 -> v3.2.0 skips (within v3)", "3.1.0", "3.2.0", false},
		{"v2.3.1 -> v2.3.2 skips (within v2)", "2.3.1", "2.3.2", false},
		{"empty current skips (fresh install)", "", "3.0.0", false},
		{"unparseable current skips", "garbage", "3.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := needsV3Migrate(tc.current, tc.next)
			if got != tc.wantMigrate {
				t.Errorf("needsV3Migrate(%q, %q) = %v; want %v",
					tc.current, tc.next, got, tc.wantMigrate)
			}
		})
	}
}

// TestExtractServiceConfigs_HappyPath verifies the helper parses
// `-config <path>` out of each service's ExecStart= line and returns a
// map keyed by service basename.
func TestExtractServiceConfigs_HappyPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anvil-a.service"), []byte(`[Service]
ExecStartPre=/opt/anvil/anvil doctor --locks-only
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-a.toml
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anvil-b.service"), []byte(`[Service]
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-b.toml
`), 0644); err != nil {
		t.Fatal(err)
	}

	got := extractServiceConfigs(dir, []string{"anvil-a", "anvil-b"})
	if len(got) != 2 {
		t.Fatalf("expected 2 configs, got %d: %v", len(got), got)
	}
	if got["anvil-a"] != "/etc/anvil/node-a.toml" {
		t.Errorf("anvil-a config: got %q want /etc/anvil/node-a.toml", got["anvil-a"])
	}
	if got["anvil-b"] != "/etc/anvil/node-b.toml" {
		t.Errorf("anvil-b config: got %q want /etc/anvil/node-b.toml", got["anvil-b"])
	}
}

// TestExtractServiceConfigs_SkipsForeignUnits verifies that a unit file
// matching the service name but invoking a different binary is skipped —
// we never try to migrate against a config that doesn't belong to anvil.
func TestExtractServiceConfigs_SkipsForeignUnits(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anvil-impostor.service"), []byte(`[Service]
ExecStart=/usr/bin/some-other-thing -config /etc/somewhere/else.toml
`), 0644); err != nil {
		t.Fatal(err)
	}
	got := extractServiceConfigs(dir, []string{"anvil-impostor"})
	if len(got) != 0 {
		t.Errorf("expected 0 (foreign binary), got %v", got)
	}
}

// TestExtractServiceConfigs_MissingConfigFlag verifies that an anvil
// unit without a -config arg is skipped (no map entry) rather than
// producing an entry pointing at an empty string.
func TestExtractServiceConfigs_MissingConfigFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anvil-a.service"), []byte(`[Service]
ExecStart=/opt/anvil/anvil
`), 0644); err != nil {
		t.Fatal(err)
	}
	got := extractServiceConfigs(dir, []string{"anvil-a"})
	if _, present := got["anvil-a"]; present {
		t.Errorf("expected anvil-a omitted (no -config flag); got %v", got)
	}
}

// TestExtractServiceConfigs_NonexistentService verifies a service whose
// unit file doesn't exist in systemdDir is silently dropped.
func TestExtractServiceConfigs_NonexistentService(t *testing.T) {
	dir := t.TempDir()
	got := extractServiceConfigs(dir, []string{"anvil-ghost"})
	if len(got) != 0 {
		t.Errorf("expected 0 (no unit file), got %v", got)
	}
}

// TestServiceRunAsUser_ParsesUserFromUnit verifies the helper extracts
// the User= directive from a service's unit file so the migrate hook
// can drop privileges to match the daemon's runtime user.
func TestServiceRunAsUser_ParsesUserFromUnit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anvil-a.service"), []byte(`[Service]
Type=simple
User=anvil
Group=anvil
ExecStart=/opt/anvil/anvil -config /etc/anvil/node-a.toml
`), 0644); err != nil {
		t.Fatal(err)
	}
	got := serviceRunAsUser(dir, []string{"anvil-a"})
	if got != "anvil" {
		t.Errorf("expected anvil, got %q", got)
	}
}

// TestServiceRunAsUser_IgnoresRootUser verifies that a unit explicitly
// running as root is skipped — we should never drop to root when the
// canonical daemon convention is a non-privileged user. Falls back to
// the next service or to the "anvil" default.
func TestServiceRunAsUser_IgnoresRootUser(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "anvil-weird.service"), []byte(`[Service]
User=root
ExecStart=/opt/anvil/anvil -config /etc/anvil/whatever.toml
`), 0644); err != nil {
		t.Fatal(err)
	}
	got := serviceRunAsUser(dir, []string{"anvil-weird"})
	if got != "anvil" {
		t.Errorf("expected fallback anvil, got %q", got)
	}
}

// TestServiceRunAsUser_DefaultsToAnvil verifies the fallback path when
// no unit file exists or no User= line is present.
func TestServiceRunAsUser_DefaultsToAnvil(t *testing.T) {
	dir := t.TempDir()
	got := serviceRunAsUser(dir, []string{"anvil-ghost"})
	if got != "anvil" {
		t.Errorf("expected default anvil, got %q", got)
	}
}

// TestAtomicCopyFile_WritesNewFile verifies the happy path: copy src to
// dst when dst doesn't yet exist.
func TestAtomicCopyFile_WritesNewFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := atomicCopyFile(src, dst, 0755); err != nil {
		t.Fatalf("atomicCopyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Errorf("content mismatch: got %q", string(got))
	}
}

// TestAtomicCopyFile_OverwritesExisting verifies that an existing dst is
// replaced correctly. This is the case that failed with ETXTBSY before
// v2.2.2 when dst was a running binary.
func TestAtomicCopyFile_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(dst, []byte("OLD VERSION"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("NEW VERSION"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := atomicCopyFile(src, dst, 0755); err != nil {
		t.Fatalf("atomicCopyFile: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "NEW VERSION" {
		t.Errorf("dst not replaced: got %q", string(got))
	}
	// Staging file should have been cleaned up via the rename.
	if _, err := os.Stat(dst + ".new"); err == nil {
		t.Error("staging file .new still present after successful rename")
	}
}
