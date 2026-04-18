package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWipeHeadersDir_RemovesLevelDBFiles verifies the header-rebuild
// remediation wipes everything under <dataDir>/headers/ without touching
// sibling dirs. This is the safety contract operators rely on when
// running doctor in fix-interactive mode — wallet/envelopes/overlay
// stores MUST survive a header wipe.
func TestWipeHeadersDir_RemovesLevelDBFiles(t *testing.T) {
	dataDir := t.TempDir()
	headersDir := filepath.Join(dataDir, "headers")
	if err := os.MkdirAll(headersDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Representative LevelDB layout: LOCK, LOG, CURRENT, MANIFEST, SST files.
	files := []string{"LOCK", "LOG", "CURRENT", "MANIFEST-000001", "000002.ldb"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(headersDir, f), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Sibling dirs that MUST NOT be touched.
	for _, sibling := range []string{"wallet", "envelopes", "overlay"} {
		sd := filepath.Join(dataDir, sibling)
		if err := os.MkdirAll(sd, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sd, "keep.ldb"), []byte("keep"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := wipeHeadersDir(dataDir); err != nil {
		t.Fatalf("wipeHeadersDir: %v", err)
	}

	// headers/ itself must still exist (only its contents were wiped).
	if _, err := os.Stat(headersDir); err != nil {
		t.Errorf("headers dir was removed entirely: %v", err)
	}
	// Every file inside headers/ should be gone.
	entries, _ := os.ReadDir(headersDir)
	if len(entries) != 0 {
		t.Errorf("headers dir still contains %d entries after wipe: %v", len(entries), entries)
	}
	// Sibling dirs must be untouched.
	for _, sibling := range []string{"wallet", "envelopes", "overlay"} {
		kept := filepath.Join(dataDir, sibling, "keep.ldb")
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("sibling file %s was destroyed by header wipe: %v", kept, err)
		}
	}
}

// TestWipeHeadersDir_MissingHeadersDir verifies the remediation returns
// a descriptive error (not a panic) when the headers dir doesn't exist —
// protects against data-dir misconfigurations.
func TestWipeHeadersDir_MissingHeadersDir(t *testing.T) {
	dataDir := t.TempDir()
	err := wipeHeadersDir(dataDir)
	if err == nil {
		t.Error("expected error for missing headers dir, got nil")
		return
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("unexpected error shape: %v", err)
	}
}

// TestConfirm_AutoYesBypassesPrompt verifies that --yes mode short-circuits
// the prompt regardless of stdin state. This is the contract the upgrade
// auto-doctor wiring relies on — unattended runs must never block waiting
// for a terminal.
func TestConfirm_AutoYesBypassesPrompt(t *testing.T) {
	// Redirect stdout to capture the auto-yes notice without polluting
	// the test log.
	saveStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = saveStdout
	})

	got := confirm(true, "fix foo?")

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if !got {
		t.Error("confirm(autoYes=true) returned false; expected true")
	}
	if !strings.Contains(buf.String(), "auto-yes") {
		t.Errorf("expected auto-yes notice in stdout, got: %q", buf.String())
	}
}
