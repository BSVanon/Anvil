package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BSVanon/Anvil/internal/refusallog"
	"github.com/BSVanon/Anvil/internal/txrelay"
)

// x402 HTTP headers per merkleworks-x402-spec v1.0.
const (
	HeaderX402Challenge = "X402-Challenge"
	HeaderX402Proof     = "X402-Proof"
	HeaderX402Receipt   = "X402-Receipt"
	// Direct payment: an Extended Format (BRC-30) tx; raw and Atomic BEEF are refused.
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
	TxID      string            `json:"txid"`
	Satoshis  int               `json:"satoshis"`
	Timestamp int64             `json:"timestamp"`
	outputs   map[string]uint64 // what the payment paid, never sent (paid_outputs_context.go)
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

	headerTip         func() uint32     // the node's header tip (checkPaymentDepth, payment_arc.go)
	replays           *paymentReplaySet // accepted direct payments (payment_replay.go)
	mu                sync.Mutex
	pendingChallenges map[string]*pendingChallenge
	reservedPending   int // places held for challenges being issued (payment_pending.go)
	maxPending        int // cap on len(pendingChallenges)+reservedPending
}

type pendingChallenge struct {
	challenge *X402Challenge
	payees    []Payee
	attempts  int // proofs counted against this challenge, guarded by PaymentGate.mu (payment_bounds.go)
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
	HeaderTip        func() uint32  // the node's header tip, nil if it has none

	// mintBudget bounds the wallet mints of a NonceProvider that is not a
	// UTXONoncePool; nil means the process-wide defaultMintBudget
	// (payment_budget.go). Only this package's tests set it.
	mintBudget *mintBudget
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
	budget := cfg.mintBudget
	if budget == nil {
		budget = defaultMintBudget
	}
	return &PaymentGate{
		priceSats:         cfg.PriceSats,
		payeeScriptHex:    cfg.PayeeScriptHex,
		nonceProvider:     withMintBudget(cfg.NonceProvider, budget),
		challengeTTL:      ttl,
		requireMempool:    cfg.RequireMempool,
		arcClient:         cfg.ARCClient,
		resolver:          cfg.Resolver,
		allowPassthrough:  cfg.AllowPassthrough,
		allowSplit:        cfg.AllowSplit,
		maxAppPriceSats:   cfg.MaxAppPriceSats,
		endpointPrices:    cfg.EndpointPrices,
		headerTip:         cfg.HeaderTip,
		replays:           newPaymentReplaySet(directPaymentReplayWindow, directPaymentReplayCapacity, time.Now),
		pendingChallenges: make(map[string]*pendingChallenge),
		maxPending:        maxPendingChallenges,
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
		r = pg.withNodePrice(r) // read per envelope (node_price_context.go)
		topic := r.URL.Query().Get("topic")
		payees, tokenGated := pg.resolvePayees(r)
		// Skip the toll only when THIS request's token gate already
		// validated a token for this exact topic; payment.go sets no auth signal.
		if tokenGated && appTokenTopicMatches(r, topic) {
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

		// X-Bsv-Payment: a raw or Extended Format tx that pays the payees
		// directly, with no challenge (verifyDirectPayment).
		if bsvPayment != "" && proofHeader == "" {
			receipt, err := pg.verifyDirectPayment(r.Context(), bsvPayment, payees)
			if err != nil {
				writePaymentRejection(w, r, "direct payment rejected: ", err)
				return
			}
			receiptJSON, _ := json.Marshal(receipt)
			w.Header().Set(HeaderX402Receipt, base64Url(receiptJSON))
			// Paid, never authenticated (withPayment, paid_outputs_context.go).
			next(w, r.WithContext(pg.withPayment(r.Context(), receipt)))
			return
		}

		receipt, err := pg.verifyProof(w, r, proofHeader)
		if err != nil {
			writePaymentRejection(w, r, "payment rejected: ", err)
			return
		}

		receiptJSON, _ := json.Marshal(receipt)
		w.Header().Set(HeaderX402Receipt, base64Url(receiptJSON))
		// Paid, never authenticated (withPayment, paid_outputs_context.go).
		next(w, r.WithContext(pg.withPayment(r.Context(), receipt)))
	}
}

// issueChallengeForPayees builds and returns a 402 challenge. In order: the
// footprint cap, the body read (payment_bodyread.go), the pending-challenge
// cap (payment_pending.go) and the budget-bounded mint (payment_budget.go).
func (pg *PaymentGate) issueChallengeForPayees(w http.ResponseWriter, r *http.Request, payees []Payee) {
	if n := challengeFootprint(r, payees); n > maxChallengeFootprint {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"request too large for a payment challenge: method, host, path, query and payee scripts are %d bytes, the limit is %d",
			n, maxChallengeFootprint))
		return
	}
	bodyBytes, ok := readChallengeBody(w, r)
	if !ok {
		return
	}
	bodyHash := sha256Hex(bodyBytes)
	headerHash := canonicalHeaderHash(r)
	place, wait, ok := pg.reservePending()
	if !ok {
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonPendingCapExceeded)
		writeUnavailable(w, wait, "too many payment challenges pending, retry later")
		return
	}
	defer place.release()

	nonce, err := pg.nonceProvider.MintNonce()
	if err != nil {
		// Classified in payment_nonce_errors.go: budget-exceeded gets 503,
		// anything else gets 500.
		writeMintNonceError(w, r, err)
		return
	}

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

	place.fill(challengeHash, &pendingChallenge{
		challenge: challenge,
		payees:    payees,
	})

	go pg.cleanExpired()

	w.Header().Set(HeaderX402Challenge, base64Url(challengeJSON))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(challenge)
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
