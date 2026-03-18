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

[forge]
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
topics = ["forge:mainnet", "oracle:rates"]

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
	if len(cfg.Forge.Seeds) != 1 || cfg.Forge.Seeds[0] != "wss://peer1.example.com:8333" {
		t.Fatalf("got forge seeds=%v", cfg.Forge.Seeds)
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
