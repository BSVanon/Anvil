package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/bond"
	"github.com/BSVanon/Anvil/internal/content"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/gossip"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/mempool"
	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/BSVanon/Anvil/internal/version"
)

// Server is the Anvil REST API server.
type Server struct {
	headerStore      *headers.Store
	proofStore       *spv.ProofStore
	envelopeStore    *envelope.Store
	overlayDir       *overlay.Directory
	validator        *spv.Validator
	broadcaster      *txrelay.Broadcaster
	gossipMgr        *gossip.Manager
	rateLimiter      *RateLimiter
	paymentGate      *PaymentGate
	tokenGate        *TokenGate
	logger           *slog.Logger
	mux              *http.ServeMux
	authToken        string
	nodeName         string
	identityPub      string
	bondChecker      *bond.Checker
	contentServer    *content.Server
	explorerOrigin   string
	publicURL        string // HTTPS public URL — used for /app/ redirects so wallet connections work
	meshTopicCache   *topicCache
	headerSyncStatus func() headers.SyncStats
	serviceHealthFn  func() string
	spvProofSource   string
	sseHub           *envelopeHub
	msgHub           *messageHub
	watcher          *mempool.Watcher
	proofFetcher     *spv.ProofFetcher
	msgStore         *messaging.Store
	signingKey       *ec.PrivateKey // node identity key for signing envelopes
	healthChecks     []HealthCheck  // registered subsystem health checks
	customCaps       []map[string]interface{}
	nodeWallet       sdk.Interface     // go-sdk wallet for canonical BRC-31 messagebox auth (nil if mesh/wallet disabled)
	msgSessions      *sessionTokenStore // 2a: per-identity SSE session tokens minted from a BRC-31 handshake
	messageboxBRC31  bool               // true when messagebox routes are served behind canonical BRC-31 mutual auth
}

// HealthCheck is a named subsystem health probe. Returns a warning string
// if the subsystem is degraded, or "" if healthy.
type HealthCheck struct {
	Name  string
	Check func() string
}

// ServerConfig holds all parameters for NewServer.
type ServerConfig struct {
	HeaderStore      *headers.Store
	ProofStore       *spv.ProofStore
	EnvelopeStore    *envelope.Store
	OverlayDir       *overlay.Directory
	Validator        *spv.Validator
	Broadcaster      *txrelay.Broadcaster
	GossipMgr        *gossip.Manager
	AuthToken        string
	RateLimit        int
	TrustProxy       bool
	PaymentSatoshis  int
	PayeeScriptHex   string
	NonceProvider    NonceProvider
	AllowPassthrough bool
	AllowSplit       bool
	AllowTokenGating bool
	MaxAppPriceSats  int
	EndpointPrices   map[string]int // per-endpoint price overrides
	ARCClient        *txrelay.ARCClient
	RequireMempool   bool
	Logger           *slog.Logger
	NodeName         string
	IdentityPub      string
	BondChecker      *bond.Checker
	P2PTxSource      content.TxSource
	P2PBlockSource   content.BlockTxSource
	HeaderLookup     func(int) string
	ExplorerOrigin   string // fallback content_origin for /explorer when catalog is empty
	PublicURL        string // HTTPS public URL for /app/ redirects (e.g. "https://anvil.sendbsv.com")
	HeaderSyncStatus func() headers.SyncStats
	// ServiceHealthFn returns this node's own service-process health as
	// "healthy" | "degraded" | "broken" | "" (unknown). Wired from main.go
	// using the diagnostics package. Used to surface service_health on
	// /mesh/status so wallet consumers can distinguish an upstream failure
	// from a local service-process meltdown. Returning "" omits the field.
	ServiceHealthFn  func() string
	SPVProofSource   string
	Watcher          *mempool.Watcher
	ProofFetcher     *spv.ProofFetcher
	MsgStore         *messaging.Store
	SigningKey       *ec.PrivateKey // node identity key for signing envelopes
	// Wallet is the node-identity go-sdk wallet. When non-nil, the BRC-33
	// messagebox routes (/sendMessage, /listMessages, /acknowledgeMessage,
	// /messages/subscribe) are served behind canonical BRC-31 mutual auth so
	// each request is authenticated by the sender's own identity key — no
	// shared operator secret in public clients. Nil (mesh/wallet disabled)
	// keeps the legacy operator-token gate.
	Wallet sdk.Interface

	// CustomCapabilities are operator-declared capability entries merged into
	// the /.well-known/anvil manifest. Lets an operator advertise AVOS oracle
	// availability, custom data relays, etc., without Anvil code changes.
	CustomCapabilities []map[string]interface{}
}

// NewServer creates a new REST API server.
func NewServer(cfg ServerConfig) *Server {
	var rl *RateLimiter
	if cfg.RateLimit > 0 {
		rl = NewRateLimiter(cfg.RateLimit, cfg.TrustProxy)
	}
	resolver := NewTopicMonetizationResolver(cfg.EnvelopeStore)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:        cfg.PaymentSatoshis,
		PayeeScriptHex:   cfg.PayeeScriptHex,
		NonceProvider:    cfg.NonceProvider,
		RequireMempool:   cfg.RequireMempool,
		ARCClient:        cfg.ARCClient,
		Resolver:         resolver,
		AllowPassthrough: cfg.AllowPassthrough,
		AllowSplit:       cfg.AllowSplit,
		MaxAppPriceSats:  cfg.MaxAppPriceSats,
		EndpointPrices:   cfg.EndpointPrices,
	})
	tg := NewTokenGate(resolver, cfg.AllowTokenGating)
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		headerStore:      cfg.HeaderStore,
		proofStore:       cfg.ProofStore,
		envelopeStore:    cfg.EnvelopeStore,
		overlayDir:       cfg.OverlayDir,
		validator:        cfg.Validator,
		broadcaster:      cfg.Broadcaster,
		gossipMgr:        cfg.GossipMgr,
		rateLimiter:      rl,
		paymentGate:      pg,
		tokenGate:        tg,
		logger:           logger,
		mux:              http.NewServeMux(),
		authToken:        cfg.AuthToken,
		nodeName:         cfg.NodeName,
		identityPub:      cfg.IdentityPub,
		bondChecker:      cfg.BondChecker,
		contentServer:    content.NewServer("", cfg.P2PTxSource, cfg.P2PBlockSource, cfg.HeaderLookup),
		explorerOrigin:   cfg.ExplorerOrigin,
		publicURL:        strings.TrimRight(cfg.PublicURL, "/"),
		meshTopicCache:   newTopicCache(10 * time.Second),
		headerSyncStatus: cfg.HeaderSyncStatus,
		serviceHealthFn:  cfg.ServiceHealthFn,
		spvProofSource:   cfg.SPVProofSource,
		sseHub:           newEnvelopeHub(),
		msgHub:           newMessageHub(),
		watcher:          cfg.Watcher,
		proofFetcher:     cfg.ProofFetcher,
		msgStore:         cfg.MsgStore,
		signingKey:       cfg.SigningKey,
		customCaps:       cfg.CustomCapabilities,
		nodeWallet:       cfg.Wallet,
	}
	if s.nodeName == "" {
		s.nodeName = "anvil"
	}
	// Wire message store notifications to SSE hub.
	if s.msgStore != nil {
		s.msgStore.SetOnMessage(func(msg *messaging.Message) {
			s.msgHub.notify(msg)
		})
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// Root redirects to Explorer when configured
	s.mux.HandleFunc("GET /{$}", cors(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/explorer", http.StatusFound)
	}))
	s.mux.HandleFunc("GET /status", s.openRead(s.handleStatus))
	s.mux.HandleFunc("GET /stats", s.openRead(s.handleStats))
	s.mux.HandleFunc("GET /mesh/status", cors(s.handleMeshStatus))
	s.mux.HandleFunc("GET /mesh/nodes", cors(s.handleMeshNodes))
	s.mux.HandleFunc("GET /headers/tip", s.openRead(s.handleHeadersTip))
	s.mux.HandleFunc("GET /headers/range", s.openRead(s.handleHeadersRange))
	// Chaintracks-compatible SPV header source for the SendBSV wallet's
	// unmodified canonical ChaintracksServiceClient (see handlers_chaintracks.go).
	// Root-mounted with the {status,value} envelope so the wallet only repoints
	// its baseURL. Mounted via openPublic (CORS + rate-limit, NO payment/token
	// gate) so these public-infrastructure reads stay unauthenticated even on a
	// node with x402 pricing enabled — the contract requires no 402/token gate.
	s.mux.HandleFunc("GET /findHeaderHexForHeight", s.openPublic(s.handleFindHeaderHexForHeight))
	s.mux.HandleFunc("GET /getPresentHeight", s.openPublic(s.handleGetPresentHeight))
	s.mux.HandleFunc("GET /tx/{txid}/beef", s.openRead(s.handleGetBEEF))
	s.mux.HandleFunc("GET /data", s.openRead(s.handleQueryData))
	s.mux.HandleFunc("GET /data/subscribe", s.openRead(s.handleSubscribe))
	s.mux.HandleFunc("DELETE /data", s.requireAuth(s.handleDeleteData))
	s.mux.HandleFunc("GET /overlay/lookup", s.openRead(s.handleOverlayLookup))

	// Topic + identity discovery (v2.0)
	s.mux.HandleFunc("GET /topics", s.openRead(s.handleListTopics))
	s.mux.HandleFunc("GET /topics/{topic...}", s.openRead(s.handleGetTopic))
	s.mux.HandleFunc("GET /identity/{pubkey}", s.openRead(s.handleGetIdentity))

	// Always register x402 discovery — shows pricing even when free (price=0).
	// Apps and Explorer use this to discover payment capabilities.
	s.mux.HandleFunc("GET /.well-known/x402", cors(s.handleX402Discovery))
	s.mux.HandleFunc("GET /.well-known/x402-info", cors(s.handleX402Info))
	s.mux.HandleFunc("GET /.well-known/anvil", cors(s.handleAnvilManifest))
	s.mux.HandleFunc("GET /.well-known/identity", cors(s.handleIdentity))
	s.mux.HandleFunc("GET /app/{name}", cors(s.handleAppRedirect))
	s.mux.HandleFunc("GET /explorer", cors(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("name", "Anvil Explorer")
		s.handleAppRedirectWithFallback(w, r, s.explorerOrigin)
	}))
	s.mux.HandleFunc("POST /bootstrap/block/{blockHash}", s.requireAuth(s.contentServer.BootstrapBlock))
	s.mux.HandleFunc("GET /content/{origin}", s.openRead(s.contentServer.ServeContent))

	// Address watching (mempool)
	s.mux.HandleFunc("POST /mempool/watch", s.requireAuth(s.handleAddWatch))
	s.mux.HandleFunc("DELETE /mempool/watch", s.requireAuth(s.handleRemoveWatch))
	s.mux.HandleFunc("GET /mempool/watch", s.openRead(s.handleListWatch))
	s.mux.HandleFunc("GET /mempool/watch/history", s.openRead(s.handleWatchHistory))
	s.mux.HandleFunc("GET /mempool/watch/subscribe", s.openRead(s.handleWatchSubscribe))

	// /broadcast accepts auth token OR x402 payment. Pre-wired for the wallet's
	// future x402 client (E.2 migration in ANVIL_NODE_HANDOFF.md) — consumers
	// with auth tokens keep working unchanged.
	s.mux.HandleFunc("POST /broadcast", s.authOrPayBinary(s.handleBroadcast))
	// POST /data accepts bearer auth OR x402 payment (if payment gate exists).
	// This lets third-party publishers submit envelopes by paying instead of
	// needing the operator's auth token.
	s.mux.HandleFunc("POST /data", s.authOrPay(s.handlePostData))
	s.mux.HandleFunc("OPTIONS /data", cors(func(w http.ResponseWriter, r *http.Request) {}))

	// v3.0.6: canonical StorageUploader stub. @bsv/sdk's StorageUploader
	// (used by SendBSV-Wallet's v14 storage-sync) calls `${host}/quote`
	// on each configured host to discover storage pricing. Anvil isn't a
	// canonical storage host yet (no /upload, no retention semantics, no
	// x402 quote pricing) — but unregistered routes return 404 without
	// CORS headers, which spams the wallet console with red errors and
	// leaves StorageUploader's resilience check unable to even reach a
	// clean "host unavailable" verdict. Returning a CORS-headered
	// `{status:"error"}` lets StorageUploader.getQuote() return null
	// cleanly (per StorageUploader.ts:152) and continue with other
	// hosts.
	//
	// Full canonical /quote + /upload implementation tracked separately
	// (see docs/internal/SENDBSV_INBOUND_DEPOSITS_REQUEST.md Ask 1
	// follow-up). v3.0.6 ships only the CORS-clean stub.
	s.mux.HandleFunc("POST /quote", cors(s.handleStorageQuoteStub))
	s.mux.HandleFunc("OPTIONS /quote", cors(func(w http.ResponseWriter, r *http.Request) {}))
	s.mux.HandleFunc("POST /overlay/register", s.requireAuth(s.handleOverlayRegister))
	s.mux.HandleFunc("POST /overlay/deregister", s.requireAuth(s.handleOverlayDeregister))

	// Node-signed publish (operator only — signs envelopes with node identity key)
	s.mux.HandleFunc("POST /node/publish", s.requireAuth(s.handleNodePublish))

	// BRC-33 messaging endpoints (point-to-point). When a node wallet is
	// available, serve them behind canonical BRC-31 mutual auth (per-identity,
	// no shared secret in public clients); otherwise fall back to the operator
	// token gate. See brc31_messagebox.go.
	if s.nodeWallet != nil {
		s.registerMessageboxBRC31()
	} else {
		s.registerMessageboxLegacy()
	}
}

// openRead wraps a handler with CORS, rate limiting, token gating, and x402 payment gating.
func (s *Server) openRead(next http.HandlerFunc) http.HandlerFunc {
	h := next
	if s.paymentGate != nil {
		h = s.paymentGate.Middleware(h)
	}
	if s.tokenGate != nil {
		h = s.tokenGate.Middleware(h)
	}
	if s.rateLimiter != nil {
		h = s.rateLimiter.Middleware(h)
	}
	// CORS: open read endpoints are public and safe to call from any origin.
	// Required for browser-based consumers like the Anvil Explorer.
	return cors(h)
}

// openPublic mounts a handler as public infrastructure: CORS + rate limiting,
// but WITHOUT the x402 payment gate or token gate. Use for endpoints that must
// serve unauthenticated on every node regardless of the operator's monetization
// config. openRead would otherwise route these through the payment gate, whose
// priceForPath charges any non-/content//.well-known/ path at the node's
// priceSats — so on a node with PriceSats>0 an openRead endpoint answers an
// unauthenticated GET with a 402 challenge. The chaintracks SPV-header source
// (findHeaderHexForHeight/getPresentHeight) does unauthenticated browser GETs
// and must never see a 402/token challenge, so it uses this path instead.
func (s *Server) openPublic(next http.HandlerFunc) http.HandlerFunc {
	h := next
	if s.rateLimiter != nil {
		h = s.rateLimiter.Middleware(h)
	}
	return cors(h)
}

// cors adds permissive CORS headers to open read endpoints. The
// Access-Control-Allow-Headers list MUST cover every custom header any
// canonical or legacy overlay route receives, otherwise browser
// preflight rejects the real request before it reaches the handler.
// Per the canonical OpenAPI spec at
// ts-stack/specs/overlay/overlay-http.yaml the canonical custom
// headers are:
//
//   - x-topics (legacy + canonical /submit; "X-Topics" preserved for
//     backward compat with existing apps)
//   - x-includes-off-chain-values (canonical /submit, vector
//     overlay.submit.8 prefixed-body opt-in)
//   - x-aggregation (canonical /lookup, vector overlay.lookup.3
//     binary-aggregated response opt-in)
//
// Codex review 2968609c62a2eb51 flagged the original list missing the
// last two — apps migrating to canonical /submit + /lookup with those
// opt-ins would have failed CORS preflight even though the routes
// themselves were CORS-wrapped.
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-App-Token, X-Anvil-Auth, X402-Proof, X-Bsv-Payment, X-Topics, x-includes-off-chain-values, x-aggregation, X-BSV-Topic")
		// Expose the /overlay/query readiness headers so browser callers can read
		// them (custom response headers are hidden from JS unless exposed).
		w.Header().Set("Access-Control-Expose-Headers", "X-Overlay-Gasp-Enabled, X-Overlay-Gasp-Initial-Sync-Done, X-Overlay-Gasp-Last-Sync-Unix, X-Overlay-Gasp-Interval-Secs")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// handleX402Discovery serves the /.well-known/x402 endpoint.
func (s *Server) handleX402Discovery(w http.ResponseWriter, r *http.Request) {
	priceFor := func(path string) int {
		if s.paymentGate != nil {
			return s.paymentGate.priceForPath(path)
		}
		return 0
	}
	gatedEndpoints := []map[string]interface{}{
		{
			"method":      "GET",
			"path":        "/status",
			"price":       priceFor("/status"),
			"description": "Node health, version, and current header height",
		},
		{
			"method":      "GET",
			"path":        "/stats",
			"price":       priceFor("/stats"),
			"description": "Extended node stats: envelope counts, active topics, mesh peers, overlay registrations",
		},
		{
			"method":      "GET",
			"path":        "/headers/tip",
			"price":       priceFor("/headers/tip"),
			"description": "Current BSV header chain tip with block hash",
		},
		{
			"method":      "GET",
			"path":        "/tx/{txid}/beef",
			"price":       priceFor("/tx/{txid}/beef"),
			"description": "SPV verification — returns transaction in BEEF format with merkle proof",
		},
		{
			"method":      "GET",
			"path":        "/data",
			"price":       priceFor("/data"),
			"description": "Query signed data envelopes by topic. Use ?topic=<name>&limit=<n>",
			"note":        "price may vary by topic monetization model",
		},
		{
			"method":      "GET",
			"path":        "/overlay/lookup",
			"price":       priceFor("/overlay/lookup"),
			"description": "Discover other nodes in the mesh via overlay registrations. Use ?topic=anvil:mainnet",
		},
		{
			"method":      "GET",
			"path":        "/mesh/status",
			"price":       0,
			"description": "Live mesh status: connected peers, active topics, data flow counters, uptime",
		},
		{
			"method":      "POST",
			"path":        "/broadcast",
			"price":       priceFor("/broadcast"),
			"description": "Submit a BEEF-validated transaction for ARC forwarding. Requires auth token OR x402 payment (authOrPay).",
			"note":        "POST; request body is binary BEEF. Returns derived status: propagated | queued | rejected | validated-only.",
		},
		{
			"method":      "GET",
			"path":        "/.well-known/anvil",
			"price":       0,
			"description": "Machine-readable manifest of this node's capabilities, payment options, and mesh info",
		},
		{
			"method":      "GET",
			"path":        "/content/{txid}_{vout}",
			"price":       0,
			"description": "Serve on-chain inscription content directly. Decentralized CDN — no GorillaPool dependency.",
		},
	}

	models := []string{"node_merchant"}
	if s.paymentGate != nil {
		if s.paymentGate.allowPassthrough {
			models = append(models, "passthrough")
		}
		if s.paymentGate.allowSplit {
			models = append(models, "split")
		}
	}
	if s.tokenGate != nil {
		models = append(models, "token")
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":        "0.1",
		"network":        "bsv-mainnet",
		"node":           s.nodeName,
		"settlement":     "BSV",
		"non_custodial":  true,
		"endpoints":      gatedEndpoints,
		"payment_models": models,
		"contact":        "https://x.com/SendBSV",
	})
}

// handleIdentity serves /.well-known/identity — node's public identity + bond status.
func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	result := map[string]interface{}{
		"node":    s.nodeName,
		"version": version.Version,
	}

	if s.identityPub != "" {
		result["identity_key"] = s.identityPub
	}

	if s.bondChecker != nil && s.bondChecker.Required() {
		result["bond"] = map[string]interface{}{
			"required": true,
			"min_sats": s.bondChecker.MinSats(),
		}
	} else {
		result["bond"] = map[string]interface{}{
			"required": false,
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// handleX402Info serves /.well-known/x402-info — a combined machine-readable
// endpoint for AI agents. Merges identity, x402 discovery, and protocol spec
// into one response. Compatible with Calhooon x402 agent discovery format.
func (s *Server) handleX402Info(w http.ResponseWriter, r *http.Request) {
	// Accept header: return markdown for LLMs, JSON for machines
	accept := r.Header.Get("Accept")
	if accept == "text/markdown" || accept == "text/plain" {
		s.serveX402InfoMarkdown(w)
		return
	}

	priceFor := func(path string) int {
		if s.paymentGate != nil {
			return s.paymentGate.priceForPath(path)
		}
		return 0
	}

	endpoints := []map[string]interface{}{
		{"method": "GET", "path": "/status", "price": priceFor("/status"), "description": "Node health and header height"},
		{"method": "GET", "path": "/stats", "price": priceFor("/stats"), "description": "Extended stats: envelopes, peers, topics"},
		{"method": "GET", "path": "/data", "price": priceFor("/data"), "description": "Query signed data envelopes by topic"},
		{"method": "GET", "path": "/tx/{txid}/beef", "price": priceFor("/tx/{txid}/beef"), "description": "SPV proof in BEEF format"},
		{"method": "GET", "path": "/overlay/lookup", "price": priceFor("/overlay/lookup"), "description": "Discover mesh peers"},
		{"method": "POST", "path": "/broadcast", "price": priceFor("/broadcast"), "description": "Submit a BEEF tx for ARC forwarding (auth token OR x402)"},
	}

	result := map[string]interface{}{
		"version":   "0.1",
		"protocol":  "anvil-x402",
		"network":   "bsv-mainnet",
		"node":      s.nodeName,
		"endpoints": endpoints,
		"payment": map[string]interface{}{
			"settlement":    "BSV",
			"non_custodial": true,
			"methods": []string{
				"X402-Challenge/Proof (nonce-bound, replay-safe)",
				"X-Bsv-Payment (direct raw tx in header, hex or base64)",
			},
			"discovery": "/.well-known/x402",
		},
		"authentication": map[string]interface{}{
			"method":         "BRC-31 mutual auth via auth.Peer",
			"key_derivation": "BRC-42",
		},
	}

	if s.identityPub != "" {
		result["identity_key"] = s.identityPub
	}

	if s.bondChecker != nil && s.bondChecker.Required() {
		result["bond"] = map[string]interface{}{
			"required": true,
			"min_sats": s.bondChecker.MinSats(),
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// serveX402InfoMarkdown returns the protocol spec as markdown for LLM consumption.
func (s *Server) serveX402InfoMarkdown(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	md := `# Anvil Node x402 Protocol

## How to pay for data on this node

This node accepts HTTP 402 micropayments in Bitcoin SV (BSV).

### Discovery
` + "GET `/.well-known/x402`" + ` — returns endpoints with prices in satoshis.
` + "GET `/.well-known/x402-info`" + ` — this document (JSON with Accept: application/json).

### Payment Method 1: Challenge-Proof (recommended)
1. Send your request without payment.
2. Receive 402 with ` + "`X402-Challenge`" + ` header (base64url JSON).
3. Build a BSV transaction spending the challenge's nonce UTXO, paying declared payees.
4. Resend request with ` + "`X402-Proof`" + ` header containing the signed proof.
5. Receive response with ` + "`X402-Receipt`" + ` header.

### Payment Method 2: Direct Payment
1. Discover pricing via ` + "`/.well-known/x402`" + `.
2. Build a BSV transaction paying the node's payee script the required satoshis.
3. Send request with ` + "`X-Bsv-Payment`" + ` header containing the raw tx (hex or base64).
4. Node verifies outputs, broadcasts to ARC, returns response with receipt.

### Authentication
BRC-31 mutual authentication via secp256k1 identity keys.
BRC-42 key derivation for payment address generation.

### Settlement
All payments settle on BSV mainnet. Non-custodial — funds go directly to payees.
No stablecoins. No payment channels. No facilitator servers.
`
	_, _ = w.Write([]byte(md))
}

// handleStorageQuoteStub returns a canonical-shaped error so the
// @bsv/sdk StorageUploader (used by SendBSV-Wallet v14 storage-sync)
// treats Anvil as an unavailable storage provider and continues with
// other configured hosts. We're not lying about being a storage host
// — we just return what the StorageUploader interprets as "this host
// doesn't have quotes right now," same shape `{status:"error"}` it
// expects per StorageUploader.ts:152.
//
// CORS headers are added by the `cors` wrapper at the route
// registration so cross-origin callers (wallet.sendbsv.com) get a
// clean preflight + response instead of the 404-without-headers
// failure that hit production 2026-05-26.
//
// Full canonical /quote + /upload implementation (real x402 pricing,
// retention semantics, BRC storage-host protocol) is a separate
// roadmap item — see docs/internal/SENDBSV_INBOUND_DEPOSITS_REQUEST.md
// follow-up.
func (s *Server) handleStorageQuoteStub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // canonical shape uses 200 + error in body, not HTTP 4xx
	_, _ = w.Write([]byte(`{"status":"error","message":"anvil-mesh does not implement canonical StorageUploader /quote yet; use POST /data for envelope upload or configure an actual storage host"}`))
}

// handleAnvilManifest serves /.well-known/anvil — a machine-readable manifest
// describing this node's identity, capabilities, and payment options.
// Designed for AI agent crawlers and discovery networks (e.g. Hyperspace Matrix).
func (s *Server) handleAnvilManifest(w http.ResponseWriter, r *http.Request) {
	tip := s.headerStore.Tip()

	// Build capabilities from live topics
	capabilities := []map[string]interface{}{}
	if s.envelopeStore != nil {
		for topic, count := range s.envelopeStore.Topics() {
			cap := map[string]interface{}{
				"type":      "data-feed",
				"topic":     topic,
				"envelopes": count,
				"access":    "GET /data?topic=" + topic,
			}
			if s.paymentGate != nil && s.paymentGate.priceForPath("/data") > 0 {
				cap["payment"] = "HTTP-402"
			} else {
				cap["payment"] = "free"
			}
			capabilities = append(capabilities, cap)
		}
	}

	// Static capabilities always available
	capabilities = append(capabilities, map[string]interface{}{
		"type":        "spv-verification",
		"description": "Verify any BSV transaction with merkle proof against synced headers",
		"access":      "GET /tx/{txid}/beef",
		"payment":     "free",
	})
	capabilities = append(capabilities, map[string]interface{}{
		"type":        "header-chain",
		"description": "Full BSV header chain synced to tip",
		"height":      tip,
		"access":      "GET /headers/tip",
		"payment":     "free",
	})

	// Operator-declared custom capabilities (e.g. AVOS oracle relay).
	// Pass-through with no schema enforcement so operators can advertise
	// capabilities Anvil itself has no native awareness of.
	capabilities = append(capabilities, s.customCaps...)

	// Mesh info
	meshInfo := map[string]interface{}{
		"gossip":    "websocket",
		"discovery": "overlay-ship",
	}
	if s.gossipMgr != nil {
		meshInfo["peers"] = s.gossipMgr.PeerCount()
	}
	if s.overlayDir != nil {
		meshInfo["known_nodes"] = s.overlayDir.CountSHIP()
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":         s.nodeName,
		"protocol":     "anvil-mesh",
		"version":      version.Version,
		"network":      "bsv-mainnet",
		"capabilities": capabilities,
		"payment": map[string]interface{}{
			"standard":      "HTTP-402",
			"settlement":    "BSV",
			"non_custodial": true,
			"discovery":     "/.well-known/x402",
		},
		"mesh":    meshInfo,
		"contact": "https://x.com/SendBSV",
		"source":  "https://github.com/BSVanon/Anvil",
	})
}

// authOrPay allows bearer auth, x402 payment, OR a valid signed envelope to
// access a write endpoint. Checked in order:
//  1. Bearer token (X-Anvil-Auth or Authorization header) — free for operator
//  2. x402 payment gate — if configured
//  3. Signed envelope — body is parsed, signature validated; proves key ownership
//     and the inscription cost is the natural spam filter
func (s *Server) authOrPay(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Handle CORS preflight for authOrPay endpoints
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-App-Token, X-Anvil-Auth, X402-Proof, X-Bsv-Payment")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Check X-Anvil-Auth first, then Authorization (same order as requireAuth)
		token := r.Header.Get("X-Anvil-Auth")
		if token == "" {
			if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
				token = auth[7:]
			}
		}
		if token != "" && s.authToken != "" && token == s.authToken {
			r.Header.Set("X-Anvil-Authed", "true")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			next(w, r)
			return
		}

		// If no valid auth token, try x402 payment
		if s.paymentGate != nil {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			s.paymentGate.Middleware(next)(w, r)
			return
		}

		// Final fallback: if the body contains a signed envelope, let it
		// through. The signature proves key ownership and the inscription
		// cost (real sats) is the natural spam filter. Ingest() will still
		// fully validate the envelope before accepting it.
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil && len(body) > 0 {
			env, parseErr := envelope.UnmarshalEnvelope(body)
			if parseErr == nil && env.Signature != "" && env.Pubkey != "" {
				if valErr := env.Validate(); valErr == nil {
					// Valid signed envelope — replay body for handler
					r.Body = io.NopCloser(bytes.NewReader(body))
					w.Header().Set("Access-Control-Allow-Origin", "*")
					next(w, r)
					return
				}
			}
			// Signature check failed — replay body so error handler can read it
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeError(w, http.StatusUnauthorized, "unauthorized — provide auth token, x402 payment, or signed envelope")
	}
}

// authOrPayBinary is authOrPay for endpoints whose request body is binary
// (e.g. /broadcast accepts raw BEEF). Differences from authOrPay:
//  1. No signed-envelope fallback — an envelope parse would corrupt the body
//     via io.LimitReader truncation for large BEEF inputs.
//  2. x402 delegation requires a positive price for the endpoint. A zero-
//     priced endpoint on a payment-gate-configured node would otherwise
//     pass through unauthenticated via resolvePayees' "no payees = free"
//     fall-through (payment_resolve.go). For binary write endpoints like
//     /broadcast this would be a high-severity auth bypass — callers could
//     relay arbitrary transactions without credentials.
//  3. When neither auth nor payment is configured on the node, returns 403
//     ("endpoint disabled") rather than 401 — consistent with the prior
//     requireAuth behavior and more accurate (server-side config issue, not
//     a caller credential issue).
func (s *Server) authOrPayBinary(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CORS preflight
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-App-Token, X-Anvil-Auth, X402-Proof, X-Bsv-Payment")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 1. Bearer token
		token := r.Header.Get("X-Anvil-Auth")
		if token == "" {
			if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
				token = auth[7:]
			}
		}
		if token != "" && s.authToken != "" && token == s.authToken {
			r.Header.Set("X-Anvil-Authed", "true")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			next(w, r)
			return
		}

		// 2. x402 payment — ONLY if this endpoint has a positive price.
		// If the operator hasn't set a broadcast price, x402 isn't a valid
		// alternative credential and we must fall through to the
		// auth-required branch below (rather than delegate to the payment
		// gate, which would pass through free for a zero-priced endpoint).
		if s.paymentGate != nil && s.paymentGate.priceForPath(r.URL.Path) > 0 {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			s.paymentGate.Middleware(next)(w, r)
			return
		}

		// 3. Endpoint disabled — neither auth nor effective payment configured
		if s.authToken == "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			writeError(w, http.StatusForbidden, "no auth token configured")
			return
		}

		// 4. Auth token configured but caller didn't supply valid one
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeError(w, http.StatusUnauthorized, "unauthorized — provide auth token or x402 payment")
	}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trust boundary: strip any client-supplied X-Anvil-Authed. This header
		// is an INTERNAL authorization signal that only the token/payment
		// middleware may set (on a validated app-token or x402 payment);
		// handlers read it to authorize read-gated content (private envelopes,
		// paid payloads). Without this strip a client could send
		// `X-Anvil-Authed: true` and — on a node with no gate configured — read
		// content it never authenticated for. Server middleware re-sets it
		// downstream on genuine success, so legitimate auth is unaffected.
		r.Header.Del("X-Anvil-Authed")
		s.mux.ServeHTTP(w, r)
	})
}

// NotifyEnvelope pushes an envelope to all SSE subscribers on its topic.
// Called by the gossip onEnvelope callback for mesh-received envelopes.
func (s *Server) NotifyEnvelope(env *envelope.Envelope) {
	s.sseHub.notify(env)
}

// NotifyMessage pushes a message to SSE subscribers on its recipient+messageBox.
// Called by the gossip onMessage callback for mesh-forwarded messages.
func (s *Server) NotifyMessage(msg *messaging.Message) {
	s.msgHub.notify(msg)
}
func (s *Server) Mux() *http.ServeMux   { return s.mux }

func (s *Server) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(next)
}

// RegisterHealthCheck adds a subsystem health probe that is evaluated on
// every /status request. The check function returns a warning string if
// the subsystem is degraded, or "" if healthy.
func (s *Server) RegisterHealthCheck(name string, check func() string) {
	s.healthChecks = append(s.healthChecks, HealthCheck{Name: name, Check: check})
}

// NoncePoolSize returns the number of ready nonces in the x402 payment gate.
// Returns 0 if no payment gate or nonce pool is configured.
func (s *Server) NoncePoolSize() int {
	if s.paymentGate == nil || s.paymentGate.nonceProvider == nil {
		return 0
	}
	if pool, ok := s.paymentGate.nonceProvider.(*UTXONoncePool); ok {
		return pool.PoolSize()
	}
	return -1 // unknown provider type, don't alarm
}

// CorsWrap adds CORS headers to a handler. Exported for use by overlay engine.
func (s *Server) CorsWrap(next http.HandlerFunc) http.HandlerFunc {
	return cors(next)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
