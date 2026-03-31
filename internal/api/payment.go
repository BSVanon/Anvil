package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

// x402 HTTP headers per merkleworks-x402-spec v1.0.
const (
	HeaderX402Challenge = "X402-Challenge"
	HeaderX402Proof     = "X402-Proof"
	HeaderX402Receipt   = "X402-Receipt"
	// Calhooon x402 compatibility: direct payment in Atomic BEEF format.
	HeaderBSVPayment = "X-Bsv-Payment"
)

// --- Challenge (server → client) ---

// Payee identifies a payment recipient in a multi-payee challenge.
// Per NON_CUSTODIAL_PAYMENT_POLICY.md, each party receives directly
// from the consumer — the node never intermediates.
type Payee struct {
	Role             string `json:"role"`               // "infrastructure" (node) or "content" (app)
	LockingScriptHex string `json:"locking_script_hex"` // P2PKH (or other) locking script
	AmountSats       int    `json:"amount_sats"`        // minimum satoshis for this payee
}

// X402Challenge is the 402 challenge per merkleworks-x402-spec v1.0,
// extended for multi-payee support (Models 2 & 3 from the non-custodial policy).
type X402Challenge struct {
	V                     int        `json:"v"`
	Scheme                string     `json:"scheme"`
	Domain                string     `json:"domain"`
	Method                string     `json:"method"`
	Path                  string     `json:"path"`
	Query                 string     `json:"query"`
	ReqHeadersSHA256      string     `json:"req_headers_sha256"`
	ReqBodySHA256         string     `json:"req_body_sha256"`
	AmountSats            int        `json:"amount_sats"`
	PayeeLockingScriptHex string     `json:"payee_locking_script_hex"`
	Payees                []Payee    `json:"payees,omitempty"`
	NonceUTXO             *NonceUTXO `json:"nonce_utxo"`
	ExpiresAt             int64      `json:"expires_at"`
	RequireMempoolAccept  bool       `json:"require_mempool_accept"`
}

// NonceUTXO identifies the UTXO the client must spend for replay protection.
type NonceUTXO struct {
	TxID             string `json:"txid"`
	Vout             int    `json:"vout"`
	Satoshis         int    `json:"satoshis"`
	LockingScriptHex string `json:"locking_script_hex"`
}

// --- Proof (client → server) ---

type X402Proof struct {
	V               int          `json:"v"`
	Scheme          string       `json:"scheme"`
	ChallengeSHA256 string       `json:"challenge_sha256"`
	Request         ProofRequest `json:"request"`
	Payment         ProofPayment `json:"payment"`
}

type ProofRequest struct {
	Method           string `json:"method"`
	Path             string `json:"path"`
	Query            string `json:"query"`
	ReqHeadersSHA256 string `json:"req_headers_sha256"`
	ReqBodySHA256    string `json:"req_body_sha256"`
}

type ProofPayment struct {
	TxID     string `json:"txid"`
	RawTxB64 string `json:"rawtx_b64"`
}

// --- Receipt (server → client) ---

type X402Receipt struct {
	TxID      string `json:"txid"`
	Satoshis  int    `json:"satoshis"`
	Timestamp int64  `json:"timestamp"`
}

// --- NonceProvider interface ---

// NonceProvider mints nonce UTXOs for 402 challenges.
type NonceProvider interface {
	MintNonce() (*NonceUTXO, error)
}

// DevNonceProvider generates deterministic nonces without real UTXOs.
// NOT replay-safe — for development/testing only.
type DevNonceProvider struct {
	counter atomic.Int64
}

func (d *DevNonceProvider) MintNonce() (*NonceUTXO, error) {
	n := d.counter.Add(1)
	h := sha256.Sum256([]byte(fmt.Sprintf("dev-nonce-%d-%d", n, time.Now().UnixNano())))
	return &NonceUTXO{
		TxID:             hex.EncodeToString(h[:]),
		Vout:             0,
		Satoshis:         1,
		LockingScriptHex: "dev-mode-no-real-utxo",
	}, nil
}

// --- PaymentGate ---

// PaymentGate holds the state for 402 payment gating.
// It is topic-aware: when a request targets a topic with monetization
// metadata, the challenge and verification adapt to the declared model.
type PaymentGate struct {
	priceSats      int
	payeeScriptHex string
	nonceProvider  NonceProvider
	challengeTTL   time.Duration
	requireMempool bool
	arcClient      *txrelay.ARCClient // for mempool acceptance verification
	resolver       *TopicMonetizationResolver

	allowPassthrough bool
	allowSplit       bool
	maxAppPriceSats  int

	// Per-endpoint pricing overrides (path → satoshis). If a path is in
	// this map, its price overrides priceSats for that endpoint.
	endpointPrices map[string]int

	mu                sync.Mutex
	pendingChallenges map[string]*pendingChallenge
}

type pendingChallenge struct {
	challenge *X402Challenge
	payees    []Payee
}

// PaymentGateConfig configures the 402 payment gate.
type PaymentGateConfig struct {
	PriceSats        int
	PayeeScriptHex   string
	NonceProvider    NonceProvider
	ChallengeTTL     time.Duration
	RequireMempool   bool
	ARCClient        *txrelay.ARCClient
	Resolver         *TopicMonetizationResolver
	AllowPassthrough bool
	AllowSplit       bool
	MaxAppPriceSats  int
	EndpointPrices   map[string]int // path → satoshis override
}

// NewPaymentGate creates a spec-compliant x402 payment gate.
// Returns nil only when no payment enforcement is possible.
func NewPaymentGate(cfg PaymentGateConfig) *PaymentGate {
	appMonetizationEnabled := cfg.AllowPassthrough || cfg.AllowSplit
	nodeCharges := cfg.PriceSats > 0

	if !nodeCharges && !appMonetizationEnabled {
		return nil
	}
	if cfg.NonceProvider == nil {
		return nil
	}
	if nodeCharges && cfg.PayeeScriptHex == "" {
		return nil
	}
	ttl := cfg.ChallengeTTL
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &PaymentGate{
		priceSats:         cfg.PriceSats,
		payeeScriptHex:    cfg.PayeeScriptHex,
		nonceProvider:     cfg.NonceProvider,
		challengeTTL:      ttl,
		requireMempool:    cfg.RequireMempool,
		arcClient:         cfg.ARCClient,
		resolver:          cfg.Resolver,
		allowPassthrough:  cfg.AllowPassthrough,
		allowSplit:        cfg.AllowSplit,
		maxAppPriceSats:   cfg.MaxAppPriceSats,
		endpointPrices:    cfg.EndpointPrices,
		pendingChallenges: make(map[string]*pendingChallenge),
	}
}

// priceForPath returns the per-endpoint price if configured, else the default.
// Infrastructure paths (/content/, /.well-known/) are always free.
func (pg *PaymentGate) priceForPath(path string) int {
	// Infrastructure paths are always free — CDN content and discovery endpoints
	if strings.HasPrefix(path, "/content/") || strings.HasPrefix(path, "/.well-known/") {
		return 0
	}
	if pg.endpointPrices != nil {
		if price, ok := pg.endpointPrices[path]; ok {
			return price
		}
	}
	return pg.priceSats
}

// Middleware returns the HTTP middleware that enforces 402 payment.
func (pg *PaymentGate) Middleware(next http.HandlerFunc) http.HandlerFunc {
	if pg == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		payees, tokenGated := pg.resolvePayees(r)
		if tokenGated {
			r.Header.Set("X-Anvil-Authed", "true")
			next(w, r)
			return
		}
		if len(payees) == 0 {
			next(w, r)
			return
		}

		proofHeader := r.Header.Get(HeaderX402Proof)
		bsvPayment := r.Header.Get(HeaderBSVPayment)

		if proofHeader == "" && bsvPayment == "" {
			pg.issueChallengeForPayees(w, r, payees)
			return
		}

		// Calhooon compatibility: x-bsv-payment contains a raw/BEEF tx
		// that pays the declared payees directly (no challenge-nonce binding).
		if bsvPayment != "" && proofHeader == "" {
			receipt, err := pg.verifyDirectPayment(bsvPayment, payees)
			if err != nil {
				writeError(w, http.StatusPaymentRequired, "direct payment rejected: "+err.Error())
				return
			}
			receiptJSON, _ := json.Marshal(receipt)
			w.Header().Set(HeaderX402Receipt, base64Url(receiptJSON))
			r.Header.Set("X-Anvil-Authed", "true")
			next(w, r)
			return
		}

		receipt, err := pg.verifyProof(r, proofHeader)
		if err != nil {
			writeError(w, http.StatusPaymentRequired, "payment rejected: "+err.Error())
			return
		}

		receiptJSON, _ := json.Marshal(receipt)
		w.Header().Set(HeaderX402Receipt, base64Url(receiptJSON))
		r.Header.Set("X-Anvil-Authed", "true")
		next(w, r)
	}
}

// issueChallengeForPayees builds and returns a 402 challenge.
func (pg *PaymentGate) issueChallengeForPayees(w http.ResponseWriter, r *http.Request, payees []Payee) {
	nonce, err := pg.nonceProvider.MintNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mint nonce: "+err.Error())
		return
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	bodyHash := sha256Hex(bodyBytes)
	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	headerHash := canonicalHeaderHash(r)

	totalSats := 0
	primaryScript := pg.payeeScriptHex
	for _, p := range payees {
		totalSats += p.AmountSats
	}
	if len(payees) == 1 {
		primaryScript = payees[0].LockingScriptHex
	}

	challenge := &X402Challenge{
		V:                     1,
		Scheme:                "bsv-tx-v1",
		Domain:                r.Host,
		Method:                r.Method,
		Path:                  r.URL.Path,
		Query:                 r.URL.RawQuery,
		ReqHeadersSHA256:      headerHash,
		ReqBodySHA256:         bodyHash,
		AmountSats:            totalSats,
		PayeeLockingScriptHex: primaryScript,
		NonceUTXO:             nonce,
		ExpiresAt:             time.Now().Add(pg.challengeTTL).Unix(),
		RequireMempoolAccept:  pg.requireMempool,
	}

	if len(payees) > 1 {
		challenge.Payees = payees
	}

	challengeJSON, _ := json.Marshal(challenge)
	challengeHash := sha256Hex(challengeJSON)

	pg.mu.Lock()
	pg.pendingChallenges[challengeHash] = &pendingChallenge{
		challenge: challenge,
		payees:    payees,
	}
	pg.mu.Unlock()

	go pg.cleanExpired()

	w.Header().Set(HeaderX402Challenge, base64Url(challengeJSON))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(challenge)
}

// cleanExpired removes challenges older than their expiry.
func (pg *PaymentGate) cleanExpired() {
	now := time.Now().Unix()
	pg.mu.Lock()
	defer pg.mu.Unlock()
	for hash, pending := range pg.pendingChallenges {
		if now > pending.challenge.ExpiresAt {
			delete(pg.pendingChallenges, hash)
		}
	}
}

// --- Helpers ---

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func base64Url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func canonicalHeaderHash(r *http.Request) string {
	bindHeaders := []string{"host", "content-type", "accept"}
	var pairs []string
	for _, name := range bindHeaders {
		val := r.Header.Get(name)
		if val == "" && name == "host" {
			val = r.Host
		}
		if val != "" {
			pairs = append(pairs, name+":"+strings.TrimSpace(val))
		}
	}
	sort.Strings(pairs)
	canonical := strings.Join(pairs, "\n") + "\n"
	return sha256Hex([]byte(canonical))
}
