package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Minimal valid TOML — only required to be parseable
	f, _ := os.CreateTemp("", "anvil-cfg-*.toml")
	f.WriteString("[node]\nname = \"test\"\n")
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Check defaults are applied
	if cfg.Node.Name != "test" {
		t.Fatalf("expected name=test, got %s", cfg.Node.Name)
	}
	if cfg.Node.DataDir != "/var/lib/anvil" {
		t.Fatalf("expected default data_dir, got %s", cfg.Node.DataDir)
	}
	if cfg.Node.Listen != "0.0.0.0:8333" {
		t.Fatalf("expected default listen, got %s", cfg.Node.Listen)
	}
	if cfg.Node.APIListen != "0.0.0.0:9333" {
		t.Fatalf("expected default api_listen, got %s", cfg.Node.APIListen)
	}
	if cfg.BSV.Nodes[0] != "seed.bitcoinsv.io:8333" {
		t.Fatalf("expected default bsv node, got %v", cfg.BSV.Nodes)
	}
	if cfg.Envelopes.MaxEphemeralTTL != 3600 {
		t.Fatalf("expected default max_ephemeral_ttl=3600, got %d", cfg.Envelopes.MaxEphemeralTTL)
	}
	if cfg.Envelopes.MaxDurableSize != 65536 {
		t.Fatalf("expected default max_durable_size=65536, got %d", cfg.Envelopes.MaxDurableSize)
	}
	if cfg.API.RateLimit != 100 {
		t.Fatalf("expected default rate_limit=100, got %d", cfg.API.RateLimit)
	}
}

func TestLoadFullConfig(t *testing.T) {
	toml := `
[node]
name = "my-node"
data_dir = "/tmp/anvil-test"
listen = "127.0.0.1:8334"
api_listen = "127.0.0.1:9334"

[identity]
wif = "Kx123"

[foundry]
seeds = ["wss://peer1.example.com:8333"]

[bsv]
nodes = ["10.0.0.1:8333", "10.0.0.2:8333"]

[arc]
enabled = true
url = "https://arc.example.com"
api_key = "secret"

[junglebus]
enabled = true
url = "junglebus.example.com"

[[junglebus.subscriptions]]
id = "sub_1"
name = "ship-tokens"
from_block = 800000

[overlay]
enabled = true
topics = ["anvil:mainnet", "oracle:rates"]

[envelopes]
max_ephemeral_ttl = 1800
max_durable_size = 32768
max_durable_store_mb = 5120
warn_at_percent = 90

[api]
auth_token = "bearer-secret"
tls_cert = "/etc/ssl/anvil.crt"
tls_key = "/etc/ssl/anvil.key"
rate_limit = 50
`
	f, _ := os.CreateTemp("", "anvil-cfg-full-*.toml")
	f.WriteString(toml)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Node.Name != "my-node" {
		t.Fatalf("got name=%s", cfg.Node.Name)
	}
	if cfg.Node.DataDir != "/tmp/anvil-test" {
		t.Fatalf("got data_dir=%s", cfg.Node.DataDir)
	}
	if cfg.Identity.WIF != "Kx123" {
		t.Fatalf("got wif=%s", cfg.Identity.WIF)
	}
	if len(cfg.Foundry.Seeds) != 1 || cfg.Foundry.Seeds[0] != "wss://peer1.example.com:8333" {
		t.Fatalf("got forge seeds=%v", cfg.Foundry.Seeds)
	}
	if !cfg.ARC.Enabled || cfg.ARC.URL != "https://arc.example.com" {
		t.Fatalf("got arc=%+v", cfg.ARC)
	}
	if !cfg.JungleBus.Enabled || len(cfg.JungleBus.Subscriptions) != 1 {
		t.Fatalf("got junglebus=%+v", cfg.JungleBus)
	}
	if cfg.JungleBus.Subscriptions[0].FromBlock != 800000 {
		t.Fatalf("got from_block=%d", cfg.JungleBus.Subscriptions[0].FromBlock)
	}
	if len(cfg.Overlay.Topics) != 2 {
		t.Fatalf("got overlay topics=%v", cfg.Overlay.Topics)
	}
	if cfg.Envelopes.MaxEphemeralTTL != 1800 {
		t.Fatalf("got max_ephemeral_ttl=%d", cfg.Envelopes.MaxEphemeralTTL)
	}
	if cfg.API.AuthToken != "bearer-secret" {
		t.Fatalf("got auth_token=%s", cfg.API.AuthToken)
	}
	if cfg.API.TLSCert != "/etc/ssl/anvil.crt" {
		t.Fatalf("got tls_cert=%s", cfg.API.TLSCert)
	}
	if cfg.API.RateLimit != 50 {
		t.Fatalf("got rate_limit=%d", cfg.API.RateLimit)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/anvil.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadBadTOML(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-bad-*.toml")
	f.WriteString("this is not valid toml [[[")
	f.Close()
	defer os.Remove(f.Name())

	_, err := Load(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestLoadOverridesDefaultsSelectively(t *testing.T) {
	// Override only node name — everything else should keep defaults
	f, _ := os.CreateTemp("", "anvil-cfg-partial-*.toml")
	f.WriteString("[node]\nname = \"partial\"\ndata_dir = \"/custom\"\n")
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Node.Name != "partial" {
		t.Fatal("name not overridden")
	}
	if cfg.Node.DataDir != "/custom" {
		t.Fatal("data_dir not overridden")
	}
	// These should still be defaults
	if cfg.Node.Listen != "0.0.0.0:8333" {
		t.Fatalf("listen should be default, got %s", cfg.Node.Listen)
	}
	if cfg.API.RateLimit != 100 {
		t.Fatalf("rate_limit should be default, got %d", cfg.API.RateLimit)
	}
}

func TestEnvVarOverrides(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-env-*.toml")
	f.WriteString("[node]\nname = \"env-test\"\n")
	f.Close()
	defer os.Remove(f.Name())

	// Set env vars — only the two that matter
	t.Setenv("ANVIL_IDENTITY_WIF", "KwEnvTestWIF")
	t.Setenv("ANVIL_TAAL_API_KEY", "taal-key-123")

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Identity.WIF != "KwEnvTestWIF" {
		t.Fatalf("expected WIF from env, got %s", cfg.Identity.WIF)
	}
	// Auth token should be auto-derived from WIF, not empty
	if cfg.API.AuthToken == "" {
		t.Fatal("expected auth token derived from WIF")
	}
	// Verify it's deterministic
	expected := deriveAuthToken("KwEnvTestWIF")
	if cfg.API.AuthToken != expected {
		t.Fatalf("expected derived token %s, got %s", expected, cfg.API.AuthToken)
	}
	// ARC should be enabled by default (GorillaPool)
	if !cfg.ARC.Enabled {
		t.Fatal("ARC should be enabled by default")
	}
	if cfg.ARC.URL != "https://arc.gorillapool.io" {
		t.Fatalf("expected default GorillaPool ARC, got %s", cfg.ARC.URL)
	}
	// TAAL failover from env
	if !cfg.ARC.TAALEnabled {
		t.Fatal("TAAL should be enabled when API key set via env")
	}
	if cfg.ARC.TAALAPIKey != "taal-key-123" {
		t.Fatalf("expected TAAL key from env, got %s", cfg.ARC.TAALAPIKey)
	}
	// JungleBus is backwards-compat-only as of v3.0.0 (W-10.5). The
	// section is still accepted by the parser but the default is
	// disabled — canonical BRC-88 SHIP/SLAP via go-sdk's LookupResolver
	// is the federation discovery path now.
	if cfg.JungleBus.Enabled {
		t.Fatal("JungleBus should default to disabled post-W-10.5 (canonical BRC-88 federation is the discovery path)")
	}
	if cfg.JungleBus.URL != "junglebus.gorillapool.io" {
		t.Fatalf("expected default JungleBus URL preserved for legacy operator configs, got %s", cfg.JungleBus.URL)
	}

	// Canonical BRC-88 federation should be enabled by default.
	if !cfg.Overlay.EnableGASPSync {
		t.Fatal("cfg.Overlay.EnableGASPSync should default to true (canonical federation is the v3.0.0 default)")
	}
}

func TestAuthTokenDerivedFromWIF(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-auth-*.toml")
	f.WriteString("[identity]\nwif = \"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S\"\n")
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.API.AuthToken == "" {
		t.Fatal("auth token should be derived from WIF")
	}

	// Load again — should produce the same token (deterministic)
	cfg2, _ := Load(f.Name())
	if cfg.API.AuthToken != cfg2.API.AuthToken {
		t.Fatal("derived auth token should be deterministic")
	}

	// Different WIF → different token
	f2, _ := os.CreateTemp("", "anvil-cfg-auth2-*.toml")
	f2.WriteString("[identity]\nwif = \"KwDifferentWIF\"\n")
	f2.Close()
	defer os.Remove(f2.Name())
	cfg3, _ := Load(f2.Name())
	if cfg.API.AuthToken == cfg3.API.AuthToken {
		t.Fatal("different WIF should produce different auth token")
	}

	t.Logf("derived token: %s (first 16 chars)", cfg.API.AuthToken[:16])
}

func TestExplicitAuthTokenOverridesDerived(t *testing.T) {
	f, _ := os.CreateTemp("", "anvil-cfg-explicit-auth-*.toml")
	f.WriteString("[identity]\nwif = \"KwSomeWIF\"\n[api]\nauth_token = \"my-custom-token\"\n")
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.API.AuthToken != "my-custom-token" {
		t.Fatalf("explicit auth_token should override derived, got %s", cfg.API.AuthToken)
	}
}

func TestEnvVarDoesNotOverrideWhenEmpty(t *testing.T) {
	toml := "[identity]\nwif = \"KwFromToml\"\n[arc]\nurl = \"https://arc.taal.com\"\n"
	f, _ := os.CreateTemp("", "anvil-cfg-noenv-*.toml")
	f.WriteString(toml)
	f.Close()
	defer os.Remove(f.Name())

	// Do NOT set any env vars — TOML values should survive
	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Identity.WIF != "KwFromToml" {
		t.Fatalf("TOML WIF should survive when no env var set, got %s", cfg.Identity.WIF)
	}
	if cfg.ARC.URL != "https://arc.taal.com" {
		t.Fatalf("TOML ARC URL should survive when no env var set, got %s", cfg.ARC.URL)
	}
}
