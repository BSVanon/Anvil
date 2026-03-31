package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
