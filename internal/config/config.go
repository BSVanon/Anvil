package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Node      NodeConfig      `toml:"node"`
	Identity  IdentityConfig  `toml:"identity"`
	Peers     PeersConfig     `toml:"peers"`
	Forge     ForgeConfig     `toml:"forge"`
	BSV       BSVConfig       `toml:"bsv"`
	ARC       ARCConfig       `toml:"arc"`
	JungleBus JungleBusConfig `toml:"junglebus"`
	Overlay   OverlayConfig   `toml:"overlay"`
	Envelopes EnvelopeConfig  `toml:"envelopes"`
	API       APIConfig       `toml:"api"`
}

// ForgeConfig defines mesh peering via go-sdk auth.Peer + WebSocket.
type ForgeConfig struct {
	Seeds []string `toml:"seeds"` // WebSocket endpoints of seed peers
}

type NodeConfig struct {
	Name      string `toml:"name"`
	DataDir   string `toml:"data_dir"`
	Listen    string `toml:"listen"`
	APIListen string `toml:"api_listen"`
}

type IdentityConfig struct {
	WIF string `toml:"wif"`
}

type PeersConfig struct {
	Seeds []string `toml:"seeds"`
}

type BSVConfig struct {
	Nodes []string `toml:"nodes"`
}

type ARCConfig struct {
	Enabled bool   `toml:"enabled"`
	URL     string `toml:"url"`
	APIKey  string `toml:"api_key"`
}

type JungleBusSubscription struct {
	ID        string `toml:"id"`
	Name      string `toml:"name"`
	FromBlock uint32 `toml:"from_block"`
}

type JungleBusConfig struct {
	Enabled       bool                    `toml:"enabled"`
	URL           string                  `toml:"url"`
	Subscriptions []JungleBusSubscription `toml:"subscriptions"`
}

type OverlayConfig struct {
	Enabled bool     `toml:"enabled"`
	Topics  []string `toml:"topics"`
}

type EnvelopeConfig struct {
	MaxEphemeralTTL   int `toml:"max_ephemeral_ttl"`
	MaxDurableSize    int `toml:"max_durable_size"`
	MaxDurableStoreMB int `toml:"max_durable_store_mb"`
	WarnAtPercent     int `toml:"warn_at_percent"`
}

type APIConfig struct {
	AuthToken string `toml:"auth_token"`
	TLSCert   string `toml:"tls_cert"`
	TLSKey    string `toml:"tls_key"`
	RateLimit int    `toml:"rate_limit"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		Node: NodeConfig{
			Name:      "anvil",
			DataDir:   "/var/lib/anvil",
			Listen:    "0.0.0.0:8333",
			APIListen: "0.0.0.0:9333",
		},
		BSV: BSVConfig{
			Nodes: []string{"seed.bitcoinsv.io:8333"},
		},
		Envelopes: EnvelopeConfig{
			MaxEphemeralTTL:   3600,
			MaxDurableSize:    65536,
			MaxDurableStoreMB: 10240,
			WarnAtPercent:     80,
		},
		API: APIConfig{
			RateLimit: 100,
		},
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}
