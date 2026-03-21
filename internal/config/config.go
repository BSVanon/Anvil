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
	Mesh      MeshConfig      `toml:"mesh"`
	Foundry   MeshConfig      `toml:"foundry"` // deprecated alias — use [mesh]
	BSV       BSVConfig       `toml:"bsv"`
	ARC       ARCConfig       `toml:"arc"`
	JungleBus JungleBusConfig `toml:"junglebus"`
	Overlay   OverlayConfig   `toml:"overlay"`
	Envelopes EnvelopeConfig  `toml:"envelopes"`
	API       APIConfig       `toml:"api"`
}

// MeshConfig defines Anvil mesh peering via go-sdk auth.Peer + WebSocket.
type MeshConfig struct {
	Seeds          []string `toml:"seeds"`            // WebSocket endpoints of seed peers
	MinBondSats    int      `toml:"min_bond_sats"`    // minimum bond UTXO required to peer (0 = no bond required)
	BondCheckURL   string   `toml:"bond_check_url"`   // UTXO lookup API (default: WoC)
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
	AuthToken        string            `toml:"auth_token"`
	TLSCert          string            `toml:"tls_cert"`
	TLSKey           string            `toml:"tls_key"`
	RateLimit        int               `toml:"rate_limit"`
	TrustProxy       bool              `toml:"trust_proxy"`
	PaymentSatoshis  int               `toml:"payment_satoshis"`    // default per-request price; 0 = free
	RequireMempool   bool              `toml:"require_mempool"`     // require ARC SEEN_ON_NETWORK before accepting x402 payment
	EndpointPrices   map[string]int    `toml:"endpoint_prices"`     // per-endpoint price overrides (path → sats)
	AppPayments      AppPaymentConfig  `toml:"app_payments"`
	ExplorerOrigin   string            `toml:"explorer_origin"`     // fallback content_origin for /explorer (survives catalog expiry)
}

// AppPaymentConfig controls which non-custodial payment models apps can use.
// Per NON_CUSTODIAL_PAYMENT_POLICY.md, the defaults are safe: all models
// enabled with a reasonable price cap. Custodial patterns (receive-and-forward,
// hold-on-behalf, revenue-share-via-wallet) are NOT configurable — they are
// hardcoded prohibitions enforced by the absence of any code path that could
// perform them.
type AppPaymentConfig struct {
	AllowPassthrough bool `toml:"allow_passthrough"` // allow apps to set their own payee scripts (Model 2)
	AllowSplit       bool `toml:"allow_split"`       // allow dual-output node+app payments (Model 3)
	AllowTokenGating bool `toml:"allow_token_gating"` // allow apps to gate via signed credentials (Model 4)
	MaxAppPriceSats  int  `toml:"max_app_price_sats"` // cap on app-declared prices; 0 = no cap
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
			Nodes: []string{
				"seed.bitcoinsv.io:8333",
				"seed.cascharia.com:8333",
				"seed.satoshisvision.network:8333",
			},
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
			Topics:  []string{"anvil:mainnet"},
		},
		Envelopes: EnvelopeConfig{
			MaxEphemeralTTL:   3600,
			MaxDurableSize:    65536,
			MaxDurableStoreMB: 10240,
			WarnAtPercent:     80,
		},
		API: APIConfig{
			RateLimit: 100,
			AppPayments: AppPaymentConfig{
				AllowPassthrough: true,
				AllowSplit:       true,
				AllowTokenGating: true,
				MaxAppPriceSats:  10000, // reasonable default cap
			},
		},
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Merge deprecated [foundry] into [mesh] for backward compatibility
	if len(cfg.Foundry.Seeds) > 0 && len(cfg.Mesh.Seeds) == 0 {
		cfg.Mesh.Seeds = cfg.Foundry.Seeds
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
