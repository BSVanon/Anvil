package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/BSVanon/Anvil/internal/bond"
	"github.com/BSVanon/Anvil/internal/content"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
)

// Server is the Anvil REST API server.
type Server struct {
	headerStore   *headers.Store
	proofStore    *spv.ProofStore
	envelopeStore *envelope.Store
	overlayDir    *overlay.Directory
	validator     *spv.Validator
	broadcaster   *txrelay.Broadcaster
	gossipMgr     *gossip.Manager
	rateLimiter   *RateLimiter
	paymentGate   *PaymentGate
	tokenGate     *TokenGate
	logger        *slog.Logger
	mux           *http.ServeMux
	authToken     string
	nodeName      string
	identityPub    string
	bondChecker     *bond.Checker
	contentServer   *content.Server
	explorerOrigin  string
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
		headerStore:   cfg.HeaderStore,
		proofStore:    cfg.ProofStore,
		envelopeStore: cfg.EnvelopeStore,
		overlayDir:    cfg.OverlayDir,
		validator:     cfg.Validator,
		broadcaster:   cfg.Broadcaster,
		gossipMgr:     cfg.GossipMgr,
		rateLimiter:   rl,
		paymentGate:   pg,
		tokenGate:     tg,
		logger:        logger,
		mux:           http.NewServeMux(),
		authToken:     cfg.AuthToken,
		nodeName:      cfg.NodeName,
		identityPub:    cfg.IdentityPub,
		bondChecker:    cfg.BondChecker,
		contentServer:   content.NewServer("", cfg.P2PTxSource, cfg.P2PBlockSource, cfg.HeaderLookup),
		explorerOrigin:  cfg.ExplorerOrigin,
	}
	if s.nodeName == "" {
		s.nodeName = "anvil"
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
	s.mux.HandleFunc("GET /headers/tip", s.openRead(s.handleHeadersTip))
	s.mux.HandleFunc("GET /tx/{txid}/beef", s.openRead(s.handleGetBEEF))
	s.mux.HandleFunc("GET /data", s.openRead(s.handleQueryData))
	s.mux.HandleFunc("GET /overlay/lookup", s.openRead(s.handleOverlayLookup))

	// Always register x402 discovery — shows pricing even when free (price=0).
	// Apps and Explorer use this to discover payment capabilities.
	s.mux.HandleFunc("GET /.well-known/x402", cors(s.handleX402Discovery))
	s.mux.HandleFunc("GET /.well-known/anvil", cors(s.handleAnvilManifest))
	s.mux.HandleFunc("GET /.well-known/identity", cors(s.handleIdentity))
	s.mux.HandleFunc("GET /app/{name}", cors(s.handleAppRedirect))
	s.mux.HandleFunc("GET /explorer", cors(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("name", "Anvil Explorer")
		s.handleAppRedirectWithFallback(w, r, s.explorerOrigin)
	}))
	s.mux.HandleFunc("POST /bootstrap/block/{blockHash}", s.requireAuth(s.contentServer.BootstrapBlock))
	s.mux.HandleFunc("GET /content/{origin}", s.openRead(s.contentServer.ServeContent))

	s.mux.HandleFunc("POST /broadcast", s.requireAuth(s.handleBroadcast))
	// POST /data accepts bearer auth OR x402 payment (if payment gate exists).
	// This lets third-party publishers submit envelopes by paying instead of
	// needing the operator's auth token.
	s.mux.HandleFunc("POST /data", s.authOrPay(s.handlePostData))
	s.mux.HandleFunc("POST /overlay/register", s.requireAuth(s.handleOverlayRegister))
	s.mux.HandleFunc("POST /overlay/deregister", s.requireAuth(s.handleOverlayDeregister))
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

// cors adds permissive CORS headers to open read endpoints.
func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-App-Token, X402-Proof")
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
			"price":       priceFor("/status"),
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
		"version": "0.1.0",
	}

	if s.identityPub != "" {
		result["identity_key"] = s.identityPub
	}

	if s.bondChecker != nil && s.bondChecker.Required() {
		result["bond"] = map[string]interface{}{
			"required":  true,
			"min_sats":  s.bondChecker.MinSats(),
		}
	} else {
		result["bond"] = map[string]interface{}{
			"required": false,
		}
	}

	writeJSON(w, http.StatusOK, result)
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
				"type":        "data-feed",
				"topic":       topic,
				"envelopes":   count,
				"access":      "GET /data?topic=" + topic,
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
		"version":      "0.1.0",
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

// authOrPay allows either bearer auth OR x402 payment to access a write endpoint.
// Bearer auth is checked first (free for the operator). If no bearer token is
// provided and a payment gate exists, x402 payment is accepted instead.
func (s *Server) authOrPay(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If bearer token is present and valid, let through
		if token := r.Header.Get("Authorization"); token != "" {
			if s.authToken != "" && token == "Bearer "+s.authToken {
				r.Header.Set("X-Anvil-Authed", "true")
				next(w, r)
				return
			}
		}

		// If no valid bearer token, try x402 payment
		if s.paymentGate != nil {
			s.paymentGate.Middleware(next)(w, r)
			return
		}

		// Neither auth nor payment available
		writeError(w, http.StatusUnauthorized, "unauthorized")
	}
}

func (s *Server) Handler() http.Handler { return s.mux }
func (s *Server) Mux() *http.ServeMux   { return s.mux }

func (s *Server) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(next)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
