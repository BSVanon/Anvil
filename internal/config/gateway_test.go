package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "anvil.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGatewayDefaults(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"test\"\n")

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Enabled {
		t.Fatal("expected gateway disabled by default")
	}
	if cfg.Gateway.TXTCacheTTL != defaultGatewayTXTCacheTTL {
		t.Fatalf("expected txt_cache_ttl=%d, got %d", defaultGatewayTXTCacheTTL, cfg.Gateway.TXTCacheTTL)
	}
	if cfg.Gateway.TXTStaleGrace != defaultGatewayTXTStaleGrace {
		t.Fatalf("expected txt_stale_grace=%d, got %d", defaultGatewayTXTStaleGrace, cfg.Gateway.TXTStaleGrace)
	}
	if cfg.Gateway.RootMaxAge != defaultGatewayRootMaxAge {
		t.Fatalf("expected root_max_age=%d, got %d", defaultGatewayRootMaxAge, cfg.Gateway.RootMaxAge)
	}
	if cfg.Gateway.ContentScope != "site" {
		t.Fatalf("expected content_scope=site, got %q", cfg.Gateway.ContentScope)
	}
	wantSites := filepath.Join(dir, "gateway-sites.conf")
	if cfg.Gateway.SitesFile != wantSites {
		t.Fatalf("expected sites_file=%q, got %q", wantSites, cfg.Gateway.SitesFile)
	}
	if cfg.Node.Mode != "" {
		t.Fatalf("expected empty mode, got %q", cfg.Node.Mode)
	}
}

func TestLoadGatewayExplicitValues(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, `
[node]
name = "gw"
mode = "gateway"

[gateway]
enabled = true
api_host = "admin.example.org"
sites_file = "/custom/sites.conf"
txt_cache_ttl = 120
txt_stale_grace = 3600
root_max_age = 30
content_scope = "any"
`)

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Gateway.Enabled {
		t.Fatal("expected gateway enabled")
	}
	if cfg.Node.Mode != "gateway" {
		t.Fatalf("expected mode=gateway, got %q", cfg.Node.Mode)
	}
	if cfg.Gateway.APIHost != "admin.example.org" {
		t.Fatalf("unexpected api_host %q", cfg.Gateway.APIHost)
	}
	if cfg.Gateway.SitesFile != "/custom/sites.conf" {
		t.Fatalf("explicit sites_file must not be overridden, got %q", cfg.Gateway.SitesFile)
	}
	if cfg.Gateway.TXTCacheTTL != 120 || cfg.Gateway.TXTStaleGrace != 3600 || cfg.Gateway.RootMaxAge != 30 {
		t.Fatalf("explicit numeric overrides not honoured: %+v", cfg.Gateway)
	}
	if cfg.Gateway.ContentScope != "any" {
		t.Fatalf("expected content_scope=any, got %q", cfg.Gateway.ContentScope)
	}
}

func TestLoadRejectsInvalidMode(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"test\"\nmode = \"bogus\"\n")

	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for an invalid [node] mode")
	}
}

func TestLoadStandardModeUnchanged(t *testing.T) {
	dir := t.TempDir()
	p := writeTestConfig(t, dir, "[node]\nname = \"test\"\nmode = \"standard\"\n")

	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Enabled {
		t.Fatal("mode=standard must not itself enable [gateway] — only an installer decides that")
	}
}
