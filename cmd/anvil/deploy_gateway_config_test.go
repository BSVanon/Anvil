package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
)

func TestRenderedGatewayConfigLoadsACMEAndMessagingPrivacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node-a.toml")
	rendered := renderGatewayConfig("a", filepath.Join(dir, "data"), dir, "gateway.example.org", "gateway", gatewayDeployArgs{
		ACMEAcceptTOS: true,
		ACMEEmail:     `ops"@example.org`,
	})
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if !cfg.Gateway.AcceptTOS {
		t.Fatal("acme_accept_tos = false, want true")
	}
	if cfg.Gateway.ACMEEmail != `ops"@example.org` {
		t.Fatalf("acme_email = %q, want escaped email", cfg.Gateway.ACMEEmail)
	}
	if cfg.Messaging.OperatorReadsAllBoxes == nil || *cfg.Messaging.OperatorReadsAllBoxes {
		t.Fatalf("operator_reads_all_boxes = %v, want false", cfg.Messaging.OperatorReadsAllBoxes)
	}
}

func TestTomlStringArray(t *testing.T) {
	if got := tomlStringArray(nil); got != "[]" {
		t.Errorf("tomlStringArray(nil) = %q, want []", got)
	}
	if got := tomlStringArray([]string{}); got != "[]" {
		t.Errorf("tomlStringArray([]) = %q, want []", got)
	}
	if got := tomlStringArray([]string{"a"}); got != `["a"]` {
		t.Errorf(`tomlStringArray(["a"]) = %q, want ["a"]`, got)
	}
	if got := tomlStringArray([]string{"a", "b"}); got != `["a", "b"]` {
		t.Errorf(`tomlStringArray(["a","b"]) = %q, want ["a", "b"]`, got)
	}
}
