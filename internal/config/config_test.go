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
topics = ["foundry:mainnet", "oracle:rates"]

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

	// Set env vars
	t.Setenv("ANVIL_IDENTITY_WIF", "KwEnvTestWIF")
	t.Setenv("ANVIL_API_AUTH_TOKEN", "secret-from-env")
	t.Setenv("ANVIL_ARC_URL", "https://arc.gorillapool.io")
	t.Setenv("ANVIL_ARC_API_KEY", "gp-key-123")
	t.Setenv("ANVIL_JUNGLEBUS_URL", "junglebus.gorillapool.io")
	t.Setenv("ANVIL_TLS_CERT", "/etc/ssl/anvil.crt")
	t.Setenv("ANVIL_TLS_KEY", "/etc/ssl/anvil.key")

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Identity.WIF != "KwEnvTestWIF" {
		t.Fatalf("expected WIF from env, got %s", cfg.Identity.WIF)
	}
	if cfg.API.AuthToken != "secret-from-env" {
		t.Fatalf("expected auth token from env, got %s", cfg.API.AuthToken)
	}
	if cfg.ARC.URL != "https://arc.gorillapool.io" {
		t.Fatalf("expected ARC URL from env, got %s", cfg.ARC.URL)
	}
	if !cfg.ARC.Enabled {
		t.Fatal("ARC should be auto-enabled when URL set via env")
	}
	if cfg.ARC.APIKey != "gp-key-123" {
		t.Fatalf("expected ARC API key from env, got %s", cfg.ARC.APIKey)
	}
	if cfg.JungleBus.URL != "junglebus.gorillapool.io" {
		t.Fatalf("expected JungleBus URL from env, got %s", cfg.JungleBus.URL)
	}
	if !cfg.JungleBus.Enabled {
		t.Fatal("JungleBus should be auto-enabled when URL set via env")
	}
	if cfg.API.TLSCert != "/etc/ssl/anvil.crt" {
		t.Fatalf("expected TLS cert from env, got %s", cfg.API.TLSCert)
	}
	if cfg.API.TLSKey != "/etc/ssl/anvil.key" {
		t.Fatalf("expected TLS key from env, got %s", cfg.API.TLSKey)
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
