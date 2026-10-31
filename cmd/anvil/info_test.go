package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestInfoRedactsTokenUnlessShowSecrets(t *testing.T) {
	const token = "very-secret-operator-token-value"
	const wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"
	sum := sha256.Sum256([]byte(token))
	fingerprint := hex.EncodeToString(sum[:])[:12]

	for _, jsonOut := range []bool{false, true} {
		var out bytes.Buffer
		writeInfo(&out, "identity", "address", token, jsonOut, false)
		got := out.String()
		if bytes.Contains([]byte(got), []byte(token)) || bytes.Contains([]byte(got), []byte(wif[:8])) {
			t.Fatalf("default info leaked a secret: %q", got)
		}
		if !bytes.Contains([]byte(got), []byte("<redacted> sha256:"+fingerprint)) {
			t.Fatalf("default info omitted fingerprint: %q", got)
		}
	}

	var shown bytes.Buffer
	writeInfo(&shown, "identity", "address", token, false, true)
	if !bytes.Contains(shown.Bytes(), []byte(token)) {
		t.Fatalf("--show-secrets output omitted token: %q", shown.String())
	}
}

func TestInfoPrintsNoneForEmptyToken(t *testing.T) {
	for _, jsonOut := range []bool{false, true} {
		var out bytes.Buffer
		writeInfo(&out, "identity", "address", "", jsonOut, false)
		if !bytes.Contains(out.Bytes(), []byte("(none)")) {
			t.Fatalf("empty token output = %q, want (none)", out.String())
		}
	}
}

func TestLoadEnvFilePathDerivation(t *testing.T) {
	// Create a temp dir with a fake env file
	dir := t.TempDir()
	envContent := "TEST_ANVIL_KEY=test_value_123\n"
	envPath := filepath.Join(dir, "node-a.env")
	if err := os.WriteFile(envPath, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Clear any existing value
	os.Unsetenv("TEST_ANVIL_KEY")

	// loadEnvFile should derive node-a.env from node-a.toml
	configPath := filepath.Join(dir, "node-a.toml")
	loadEnvFile(configPath)

	got := os.Getenv("TEST_ANVIL_KEY")
	if got != "test_value_123" {
		t.Fatalf("expected TEST_ANVIL_KEY=test_value_123, got %q", got)
	}

	// Clean up
	os.Unsetenv("TEST_ANVIL_KEY")
}

func TestLoadEnvFileNoTraversal(t *testing.T) {
	// Create a temp dir structure: parent/sub/node-a.toml
	// and parent/node-a.env (should NOT be loaded)
	parent := t.TempDir()
	sub := filepath.Join(parent, "sub")
	os.MkdirAll(sub, 0755)

	// Put env file in parent (traversal target)
	os.WriteFile(filepath.Join(parent, "node-a.env"), []byte("TRAVERSAL_KEY=bad\n"), 0600)

	// Put env file in sub (correct location)
	os.WriteFile(filepath.Join(sub, "node-a.env"), []byte("TRAVERSAL_KEY=good\n"), 0600)

	os.Unsetenv("TRAVERSAL_KEY")

	// Config path in sub — should load sub/node-a.env, not parent/node-a.env
	loadEnvFile(filepath.Join(sub, "node-a.toml"))

	got := os.Getenv("TRAVERSAL_KEY")
	if got != "good" {
		t.Fatalf("expected TRAVERSAL_KEY=good, got %q (traversal may have occurred)", got)
	}

	os.Unsetenv("TRAVERSAL_KEY")
}

func TestLoadEnvFileMissing(t *testing.T) {
	// loadEnvFile with nonexistent config should not panic
	loadEnvFile("/nonexistent/path/node-x.toml")
}
