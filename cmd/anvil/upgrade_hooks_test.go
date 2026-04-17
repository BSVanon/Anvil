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
	wantHook := "ExecStartPre=/opt/anvil/anvil doctor --fix-locks-only"
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

// TestEnsureExecStartPreHook_IdempotentOnExistingHook verifies a unit
// that already has the hook is not modified (counter stays 0).
func TestEnsureExecStartPreHook_IdempotentOnExistingHook(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "anvil-a.service")
	original := `[Service]
ExecStartPre=/opt/anvil/anvil doctor --fix-locks-only
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
	if strings.Contains(string(got), "doctor --fix-locks-only") {
		t.Error("hook leaked into unrelated unit file")
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
