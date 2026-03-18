package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Node      NodeConfig      `toml:"node"`
	Identity  IdentityConfig  `toml:"identity"`
	Peers     PeersConfig     `toml:"peers"`
	Foundry   FoundryConfig   `toml:"foundry"`
	BSV       BSVConfig       `toml:"bsv"`
	ARC       ARCConfig       `toml:"arc"`
	JungleBus JungleBusConfig `toml:"junglebus"`
	Overlay   OverlayConfig   `toml:"overlay"`
	Envelopes EnvelopeConfig  `toml:"envelopes"`
	API       APIConfig       `toml:"api"`
}

// FoundryConfig defines mesh peering via go-sdk auth.Peer + WebSocket.
type FoundryConfig struct {
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
	Enabled      bool   `toml:"enabled"`
	URL          string `toml:"url"`           // primary ARC (default: GorillaPool, free)
	APIKey       string `toml:"api_key"`       // for primary ARC if it requires auth
	TAALEnabled  bool   `toml:"taal_enabled"`  // optional TAAL failover
	TAALURL      string `toml:"taal_url"`      // default: https://arc.taal.com
	TAALAPIKey   string `toml:"taal_api_key"`  // TAAL API key (recommended but not required)
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
	AuthToken  string `toml:"auth_token"`
	TLSCert    string `toml:"tls_cert"`
	TLSKey     string `toml:"tls_key"`
	RateLimit  int    `toml:"rate_limit"`
	TrustProxy bool   `toml:"trust_proxy"` // if true, use X-Forwarded-For for client IP; if false, use RemoteAddr only
	PaymentSatoshis int `toml:"payment_satoshis"` // per-request price for 402-gated endpoints; 0 = free
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
		ARC: ARCConfig{
			Enabled: true,
			URL:     "https://arc.gorillapool.io",
			TAALURL: "https://arc.taal.com",
		},
		JungleBus: JungleBusConfig{
			Enabled: true,
			URL:     "junglebus.gorillapool.io",
		},
		Overlay: OverlayConfig{
			Enabled: true,
			Topics:  []string{"foundry:mainnet"},
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

	// Environment variable overrides
	if v := os.Getenv("ANVIL_IDENTITY_WIF"); v != "" {
		cfg.Identity.WIF = v
	}
	if v := os.Getenv("ANVIL_TAAL_API_KEY"); v != "" {
		cfg.ARC.TAALAPIKey = v
		cfg.ARC.TAALEnabled = true
	}

	// Derive API auth token from WIF if not explicitly set.
	// HMAC(key=WIF, msg="anvil-api-auth") → deterministic 32-byte hex token.
	// Anyone who knows the WIF can compute this — which is the right trust model
	// because the WIF IS the root of trust for the node.
	if cfg.API.AuthToken == "" && cfg.Identity.WIF != "" {
		cfg.API.AuthToken = deriveAuthToken(cfg.Identity.WIF)
	}

	return cfg, nil
}

// deriveAuthToken deterministically derives an API bearer token from a WIF.
// Uses HMAC-SHA256 so the token is stable across restarts.
func deriveAuthToken(wif string) string {
	mac := hmac.New(sha256.New, []byte(wif))
	mac.Write([]byte("anvil-api-auth"))
	return hex.EncodeToString(mac.Sum(nil))
}
