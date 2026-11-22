package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Node         NodeConfig         `toml:"node"`
	Identity     IdentityConfig     `toml:"identity"`
	Peers        PeersConfig        `toml:"peers"`
	Mesh         MeshConfig         `toml:"mesh"`
	Foundry      MeshConfig         `toml:"foundry"` // deprecated alias — use [mesh]
	BSV          BSVConfig          `toml:"bsv"`
	ARC          ARCConfig          `toml:"arc"`
	JungleBus    JungleBusConfig    `toml:"junglebus"`
	Overlay      OverlayConfig      `toml:"overlay"`
	Envelopes    EnvelopeConfig     `toml:"envelopes"`
	Messaging    MessagingConfig    `toml:"messaging"`
	Mempool      MempoolConfig      `toml:"mempool"`
	API          APIConfig          `toml:"api"`
	Capabilities CapabilitiesConfig `toml:"capabilities"`
	Gateway      GatewayConfig      `toml:"gateway"`
	Content      ContentConfig      `toml:"content"`
	CertGate     CertGateConfig     `toml:"certgate"`
}

// CapabilitiesConfig holds custom entries surfaced in /.well-known/anvil.
// The entries let machine consumers discover operator-provided services.
type CapabilitiesConfig struct {
	// Custom is a freeform list of capability entries. Each entry is a
	// map[string]interface{} so operators can include any fields relevant
	// to the capability type without requiring schema changes in Anvil.
	// Recommended fields per capability: "type", "description", "access",
	// "payment". Additional fields pass through as-is.
	Custom []map[string]interface{} `toml:"custom"`
}

type NodeConfig struct {
	Name      string `toml:"name"`
	DataDir   string `toml:"data_dir"`
	Listen    string `toml:"listen"`
	APIListen string `toml:"api_listen"`
	PublicURL string `toml:"public_url"` // public-facing API URL for overlay registration (e.g. "https://anvil.sendbsv.com")

	// Mode is "standard" (default) or "gateway" — only changes installer
	// defaults (internal/gateway); nothing here branches on it at runtime.
	Mode string `toml:"mode"`
}

type IdentityConfig struct {
	WIF string `toml:"wif"`
}

type PeersConfig struct {
	Seeds []string `toml:"seeds"`
}

type ARCConfig struct {
	Enabled     bool   `toml:"enabled"`
	URL         string `toml:"url"`          // primary ARC (default: GorillaPool, free)
	APIKey      string `toml:"api_key"`      // for primary ARC if it requires auth
	TAALEnabled bool   `toml:"taal_enabled"` // optional TAAL failover
	TAALURL     string `toml:"taal_url"`     // default: https://arc.taal.com
	TAALAPIKey  string `toml:"taal_api_key"` // TAAL API key (recommended but not required)
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

	// EnableGASPSync controls participation in canonical BRC-88
	// SHIP/SLAP federation. When true (default), the v3 engine
	// advertises this node's hosted topics on-chain via the canonical
	// Advertiser, discovers federation peers via SHIP/SLAP trackers,
	// and runs periodic GASP sync against discovered peers. Operators
	// who want pure single-node operation set this to false. Disabling
	// only suppresses *outbound* federation; inbound GASP routes
	// (/requestSyncResponse, /requestForeignGASPNode) remain served
	// because they expose state we already index locally.
	EnableGASPSync bool `toml:"enable_gasp_sync"`

	// SHIPTrackers / SLAPTrackers are bootstrap URLs for canonical
	// BRC-88 service discovery. Empty values fall back to go-sdk's
	// DEFAULT_SLAP_TRACKERS (overlay/lookup.DEFAULT_SLAP_TRACKERS),
	// which lists Project Babbage's public infrastructure. Operators
	// can override to point at their own federation, an internal
	// staging tracker, or a regional preference.
	SHIPTrackers []string `toml:"ship_trackers"`
	SLAPTrackers []string `toml:"slap_trackers"`

	// NamedPeers is a closed-network allowlist of overlay base URLs.
	// Empty means today's behaviour, including the public_url
	// requirement below. Entries are trimmed; blank entries are
	// skipped (cmd/anvil's sanitizeNamedPeers), so a stray blank string
	// doesn't count as "set".
	//
	// When set, GASP sync wiring (lookup federation, SHIP/SLAP
	// resolution, and sync for every topic — not just tm_ship/tm_slap)
	// is wired regardless of [node] public_url, so a node can peer with
	// named nodes and run GASP catch-up with no public_url at all.
	// ship_trackers / slap_trackers and go-sdk's DEFAULT_SLAP_TRACKERS
	// fallback are not consulted in this mode, and the baked-in default
	// header-fallback peer is not appended either (see
	// ensureHeaderFallbackPeers).
	//
	// The SHIP/SLAP Advertiser is NEVER constructed when NamedPeers is
	// set, even if public_url is also set: an advert transaction would
	// still reach the configured Broadcaster/ARC and permanently link
	// this node's identity on-chain — the exact outcome closed-network
	// mode exists to prevent. See cmd/anvil's wireV3Federation.
	NamedPeers []string `toml:"named_peers"`

	// GASPSyncIntervalSecs is how often we pull canonical federation
	// state from discovered peers (every N seconds). v3.0.0-v3.0.6
	// hardcoded this at 300s (5 min), inherited from overlay-express
	// defaults. In production that translates to ~3 Mbps sustained RX
	// on small VPSes because the canonical engine re-requests
	// advertisements with since=0 each cycle (no cursor persistence
	// yet — see v3.0.8 candidate work). v3.0.7 bumps the default to
	// 1800 (30 min) to match SyncAdvertisements + cut bandwidth ~6x.
	// Operators who want faster discovery can dial back down; aim for
	// 60s as a floor or you'll hit upstream tracker rate limits.
	// 0 or unset → default 1800.
	GASPSyncIntervalSecs int `toml:"gasp_sync_interval_secs"`

	// GASPSyncRunTimeoutSecs caps one complete GASP sync run, including all
	// topics, peers and pages. 0 or unset → default 600 seconds. This keeps a
	// peer that continues to make bounded per-page progress from monopolizing
	// the serial sync loop indefinitely.
	GASPSyncRunTimeoutSecs int `toml:"gasp_sync_run_timeout_secs"`

	// AdvertiseIntervalSecs is how often the canonical Advertiser
	// reconciles our own SHIP/SLAP outputs against the hosted topic
	// set. Historically hardcoded at 1800s; the field exists for
	// symmetry with GASPSyncIntervalSecs. 0 or unset → default 1800.
	AdvertiseIntervalSecs int `toml:"advertise_interval_secs"`
}

// MempoolConfig controls P2P mempool transaction monitoring.
// When enabled, the node maintains a long-lived connection to a BSV peer
// and selectively indexes transactions matching its coverage filter.
type MempoolConfig struct {
	Enabled    bool  `toml:"enabled"`     // opt-in (default: false)
	Prefixes   []int `toml:"prefixes"`    // explicit coverage bytes (0-255); empty = auto
	MaxTxSize  int   `toml:"max_tx_size"` // skip txs larger than this (bytes, 0 = no limit)
	TTLSeconds int   `toml:"ttl_seconds"` // evict entries older than this
}

type EnvelopeConfig struct {
	MaxEphemeralTTL   int `toml:"max_ephemeral_ttl"`
	MaxDurableSize    int `toml:"max_durable_size"`
	MaxDurableStoreMB int `toml:"max_durable_store_mb"`
	WarnAtPercent     int `toml:"warn_at_percent"`
}

type APIConfig struct {
	AuthToken           string           `toml:"auth_token"`
	TLSCert             string           `toml:"tls_cert"`
	TLSKey              string           `toml:"tls_key"`
	RateLimit           int              `toml:"rate_limit"`
	TrustProxy          bool             `toml:"trust_proxy"`
	TrustProxyHops      int              `toml:"trust_proxy_hops"`
	MessageboxRateLimit int              `toml:"messagebox_rate_limit"`
	MessageboxRateBurst int              `toml:"messagebox_rate_burst"`
	PaymentSatoshis     int              `toml:"payment_satoshis"`      // default per-request price; 0 = free
	RequireMempool      bool             `toml:"require_mempool"`       // require ARC SEEN_ON_NETWORK or MINED before accepting an X402-Proof; refused without ARC
	EndpointPrices      map[string]int   `toml:"endpoint_prices"`       // per-endpoint price overrides (path → sats)
	X402ProofScheme     bool             `toml:"x402_proof_scheme"`     // deprecated development-only proof scheme; default false
	X402MintBurst       int              `toml:"x402_mint_burst"`       // proof nonce budget; only used with x402_proof_scheme
	X402MintsPerMinute  int              `toml:"x402_mints_per_minute"` // proof nonce rate; only used with x402_proof_scheme
	AppPayments         AppPaymentConfig `toml:"app_payments"`
	ExplorerOrigin      string           `toml:"explorer_origin"` // fallback content_origin for /explorer (survives catalog expiry)
	NoncePoolSize       int              `toml:"nonce_pool_size"` // charging-node proof nonce target; only with x402_proof_scheme; 0 defaults to 100
}

// AppPaymentConfig controls which non-custodial payment models apps can use.
// Per NON_CUSTODIAL_PAYMENT_POLICY.md, the defaults are safe: all models
// enabled with a reasonable price cap. Custodial patterns (receive-and-forward,
// hold-on-behalf, revenue-share-via-wallet) are NOT configurable — they are
// hardcoded prohibitions enforced by the absence of any code path that could
// perform them.
type AppPaymentConfig struct {
	AllowPassthrough bool `toml:"allow_passthrough"`  // allow apps to set their own payee scripts (Model 2)
	AllowSplit       bool `toml:"allow_split"`        // allow dual-output node+app payments (Model 3)
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
		Mesh: defaultMeshConfig(),
		BSV: BSVConfig{
			Nodes:                  append([]string(nil), defaultBSVSeeds...),
			HeaderSyncIntervalSecs: 30,
			HeaderStaleAfterSecs:   defaultHeaderStaleAfterSecs,
		},
		ARC: ARCConfig{
			Enabled: true,
			URL:     "https://arc.gorillapool.io",
			TAALURL: "https://arc.taal.com",
		},
		// JungleBus is backwards-compatibility-only as of v3.0.0
		// . The bespoke SHIP/SLAP discovery + on-chain publish
		// paths it powered have been retired in favor of canonical
		// BRC-88 SHIP/SLAP via go-sdk's LookupResolver — see
		// built-in federation. The TOML parser still
		// accepts this section so legacy anvil.toml files don't break,
		// but every field below is a runtime no-op. Default is
		// disabled to avoid suggesting the old path is still active.
		JungleBus: JungleBusConfig{
			Enabled: false,
			URL:     "junglebus.gorillapool.io",
		},
		Overlay: OverlayConfig{
			Enabled:                true,
			Topics:                 []string{"anvil:mainnet"},
			EnableGASPSync:         true,
			GASPSyncIntervalSecs:   1800, // v3.0.7 default — was hardcoded 300s pre-v3.0.7
			GASPSyncRunTimeoutSecs: 600,
			AdvertiseIntervalSecs:  1800, // matches SyncAdvertisements historic cadence
			// SHIPTrackers + SLAPTrackers left blank by default; canonical
			// wiring in cmd/anvil/main.go falls back to go-sdk's
			// overlay/lookup.DEFAULT_SLAP_TRACKERS (Project Babbage's
			// public BSVA US/EU/AP + users.bapp.dev hosts) when the
			// operator hasn't supplied explicit URLs.
		},
		Mempool: MempoolConfig{
			Enabled:    false,
			MaxTxSize:  1 << 20, // 1 MB
			TTLSeconds: 3600,    // 1 hour
		},
		Envelopes: EnvelopeConfig{
			MaxEphemeralTTL:   3600,
			MaxDurableSize:    65536,
			MaxDurableStoreMB: 10240,
			WarnAtPercent:     80,
		},
		Messaging: defaultMessagingConfig(),
		API: APIConfig{
			RateLimit:           100,
			TrustProxyHops:      1,
			MessageboxRateLimit: 20,
			MessageboxRateBurst: 40,
			NoncePoolSize:       100,
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
	if err := finalizeCertGate(data, cfg); err != nil {
		return nil, err
	}
	if cfg.API.X402ProofScheme {
		log.Printf("x402: x402_proof_scheme is deprecated and for development only")
	}
	if cfg.API.TrustProxyHops < 1 {
		cfg.API.TrustProxyHops = 1
	}
	if cfg.API.MessageboxRateLimit <= 0 {
		cfg.API.MessageboxRateLimit = 20
	}
	if cfg.API.MessageboxRateBurst <= 0 {
		cfg.API.MessageboxRateBurst = 40
	}
	if cfg.BSV.HeaderStaleAfterSecs == 0 {
		cfg.BSV.HeaderStaleAfterSecs = defaultHeaderStaleAfterSecs
	}
	if cfg.Messaging.TTLSeconds <= 0 {
		cfg.Messaging.TTLSeconds = 604800
	}
	if cfg.Messaging.MaxPairMessages <= 0 {
		cfg.Messaging.MaxPairMessages = 1000
	}
	if cfg.Messaging.MaxPairBytes <= 0 {
		cfg.Messaging.MaxPairBytes = 64 << 20
	}
	if cfg.Messaging.MaxStoreMessages <= 0 {
		cfg.Messaging.MaxStoreMessages = 1000000
	}
	if cfg.Messaging.MaxStoreBytes <= 0 {
		cfg.Messaging.MaxStoreBytes = 2 << 30
	}
	if cfg.Messaging.MaxInboxMessages < 0 {
		cfg.Messaging.MaxInboxMessages = 0
	}
	if cfg.Messaging.MaxInboxBytes < 0 {
		cfg.Messaging.MaxInboxBytes = 0
	}
	if err := normalizeMessagingPrivacy(&cfg.Messaging); err != nil {
		return nil, fmt.Errorf("messaging privacy config: %w", err)
	}
	if err := validatePrivateHomeNetwork(&cfg.Messaging, &cfg.Mesh); err != nil {
		return nil, err
	}
	if err := validatePrivateHomeWatchCapacity(&cfg.Messaging, &cfg.CertGate); err != nil {
		return nil, err
	}

	if err := finalizeGateway(cfg, path); err != nil {
		return nil, err
	}
	if err := finalizeContent(&cfg.Content); err != nil {
		return nil, err
	}

	if err := finalizeMeshConfig(&cfg.Mesh, cfg.Foundry); err != nil {
		return nil, err
	}

	// Guarantee the BSV header-sync peer list always carries the canonical
	// fallback seeds. Older `anvil deploy` templates wrote a single peer
	// (seed.bitcoinsv.io:8333); when that seed drops the P2P handshake the syncer
	// has nothing to rotate to and headers go stale. Appending the defaults here
	// repairs those configs at runtime — the fix takes effect on `anvil upgrade`
	// with no config edit required.
	cfg.BSV.Nodes = ensureFallbackSeeds(cfg.BSV.Nodes)

	// Bake the canonical header-fallback peer into every config (unless the
	// operator disabled it), minus this node's own public URL. This makes the
	// mesh header self-heal automatic on `anvil upgrade` — no per-node config edit
	// — mirroring the default BSV seeds above. Consulted when P2P sync fails or the
	// stored tip is stale. A closed-network node ([overlay] named_peers set) never
	// gets the baked-in default appended here either — only its own explicitly
	// configured header_fallback_peers apply.
	cfg.BSV.HeaderFallbackPeers = ensureHeaderFallbackPeers(cfg.BSV.HeaderFallbackPeers, cfg.Node.PublicURL, cfg.BSV.HeaderFallbackDisabled, len(cfg.Overlay.NamedPeers) > 0)

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
