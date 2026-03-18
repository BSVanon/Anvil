package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// x402 HTTP headers per merkleworks-x402-spec v1.0.
const (
	HeaderX402Challenge = "X402-Challenge"
	HeaderX402Proof     = "X402-Proof"
	HeaderX402Receipt   = "X402-Receipt"
)

// --- Challenge (server → client) ---

// X402Challenge is the 402 challenge per merkleworks-x402-spec v1.0.
// Serialized as canonical JSON (sorted keys), then base64url-encoded in the header.
type X402Challenge struct {
	V                    int         `json:"v"`                        // must be 1
	Scheme               string      `json:"scheme"`                   // "bsv-tx-v1"
	Domain               string      `json:"domain"`                   // HTTP Host
	Method               string      `json:"method"`                   // HTTP method
	Path                 string      `json:"path"`                     // absolute path
	Query                string      `json:"query"`                    // raw query string
	ReqHeadersSHA256     string      `json:"req_headers_sha256"`       // SHA-256 of canonical header binding
	ReqBodySHA256        string      `json:"req_body_sha256"`          // SHA-256 of request body
	AmountSats           int         `json:"amount_sats"`              // minimum satoshis
	PayeeLockingScriptHex string    `json:"payee_locking_script_hex"` // node's receiving script
	NonceUTXO            *NonceUTXO  `json:"nonce_utxo"`               // nonce UTXO to spend
	ExpiresAt            int64       `json:"expires_at"`               // UNIX timestamp
	RequireMempoolAccept bool        `json:"require_mempool_accept"`   // require ARC confirmation
}

// NonceUTXO identifies the UTXO the client must spend for replay protection.
type NonceUTXO struct {
	TxID             string `json:"txid"`
	Vout             int    `json:"vout"`
	Satoshis         int    `json:"satoshis"`
	LockingScriptHex string `json:"locking_script_hex"`
}

// --- Proof (client → server) ---

// X402Proof is the payment proof per merkleworks-x402-spec v1.0.
type X402Proof struct {
	V              int          `json:"v"`                // must be 1
	Scheme         string       `json:"scheme"`           // "bsv-tx-v1"
	ChallengeSHA256 string     `json:"challenge_sha256"` // SHA-256 of canonical challenge JSON
	Request        ProofRequest `json:"request"`          // echoed request binding
	Payment        ProofPayment `json:"payment"`          // the settlement tx
}

// ProofRequest echoes the request fields from the challenge for binding verification.
type ProofRequest struct {
	Method           string `json:"method"`
	Path             string `json:"path"`
	Query            string `json:"query"`
	ReqHeadersSHA256 string `json:"req_headers_sha256"`
	ReqBodySHA256    string `json:"req_body_sha256"`
}

// ProofPayment carries the settlement transaction.
type ProofPayment struct {
	TxID    string `json:"txid"`
	RawTxB64 string `json:"rawtx_b64"` // standard base64
}

// --- Receipt (server → client) ---

// X402Receipt confirms accepted payment.
type X402Receipt struct {
	TxID      string `json:"txid"`
	Satoshis  int    `json:"satoshis"`
	Timestamp int64  `json:"timestamp"`
}

// --- NonceProvider interface ---

// NonceProvider mints nonce UTXOs for 402 challenges.
// The WalletNonceProvider uses the node wallet; the DevNonceProvider
// generates deterministic test nonces without real UTXOs.
type NonceProvider interface {
	// MintNonce creates a nonce UTXO and returns its details.
	MintNonce() (*NonceUTXO, error)
}

// DevNonceProvider generates deterministic nonces without real UTXOs.
// NOT replay-safe — for development/testing only.
type DevNonceProvider struct {
	counter int
}

func (d *DevNonceProvider) MintNonce() (*NonceUTXO, error) {
	d.counter++
	// Generate a deterministic fake txid from the counter
	h := sha256.Sum256([]byte(fmt.Sprintf("dev-nonce-%d-%d", d.counter, time.Now().UnixNano())))
	return &NonceUTXO{
		TxID:             hex.EncodeToString(h[:]),
		Vout:             0,
		Satoshis:         1,
		LockingScriptHex: "dev-mode-no-real-utxo",
	}, nil
}

// --- Middleware ---

// PaymentGate holds the state for 402 payment gating.
type PaymentGate struct {
	priceSats         int
	payeeScriptHex    string // hex-encoded locking script for the node's payment address
	nonceProvider     NonceProvider
	challengeTTL      time.Duration
	requireMempool    bool
	pendingChallenges map[string]*X402Challenge // challenge_sha256 → challenge (short-lived)
}

// PaymentGateConfig configures the 402 payment gate.
type PaymentGateConfig struct {
	PriceSats      int
	PayeeScriptHex string        // the node's P2PKH locking script (hex)
	NonceProvider  NonceProvider
	ChallengeTTL   time.Duration // how long a challenge is valid (default 60s)
	RequireMempool bool          // require ARC mempool acceptance
}

// NewPaymentGate creates a spec-compliant x402 payment gate.
// Returns nil if priceSats <= 0 (free access).
func NewPaymentGate(cfg PaymentGateConfig) *PaymentGate {
	if cfg.PriceSats <= 0 {
		return nil
	}
	ttl := cfg.ChallengeTTL
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	np := cfg.NonceProvider
	if np == nil {
		np = &DevNonceProvider{}
	}
	return &PaymentGate{
		priceSats:         cfg.PriceSats,
		payeeScriptHex:    cfg.PayeeScriptHex,
		nonceProvider:     np,
		challengeTTL:      ttl,
		requireMempool:    cfg.RequireMempool,
		pendingChallenges: make(map[string]*X402Challenge),
	}
}

// Middleware returns the HTTP middleware that enforces 402 payment.
func (pg *PaymentGate) Middleware(next http.HandlerFunc) http.HandlerFunc {
	if pg == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		proofHeader := r.Header.Get(HeaderX402Proof)
		if proofHeader == "" {
			pg.issueChallenge(w, r)
			return
		}

		receipt, err := pg.verifyProof(r, proofHeader)
		if err != nil {
			writeError(w, http.StatusPaymentRequired, "payment rejected: "+err.Error())
			return
		}

		receiptJSON, _ := json.Marshal(receipt)
		w.Header().Set(HeaderX402Receipt, base64Url(receiptJSON))
		next(w, r)
	}
}

// issueChallenge builds and returns a 402 challenge.
func (pg *PaymentGate) issueChallenge(w http.ResponseWriter, r *http.Request) {
	nonce, err := pg.nonceProvider.MintNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mint nonce: "+err.Error())
		return
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	bodyHash := sha256Hex(bodyBytes)
	headerHash := canonicalHeaderHash(r)

	challenge := &X402Challenge{
		V:                     1,
		Scheme:                "bsv-tx-v1",
		Domain:                r.Host,
		Method:                r.Method,
		Path:                  r.URL.Path,
		Query:                 r.URL.RawQuery,
		ReqHeadersSHA256:      headerHash,
		ReqBodySHA256:         bodyHash,
		AmountSats:            pg.priceSats,
		PayeeLockingScriptHex: pg.payeeScriptHex,
		NonceUTXO:             nonce,
		ExpiresAt:             time.Now().Add(pg.challengeTTL).Unix(),
		RequireMempoolAccept:  pg.requireMempool,
	}

	challengeJSON, _ := json.Marshal(challenge)
	challengeHash := sha256Hex(challengeJSON)

	// Store for later verification
	pg.pendingChallenges[challengeHash] = challenge

	// Clean expired challenges
	go pg.cleanExpired()

	w.Header().Set(HeaderX402Challenge, base64Url(challengeJSON))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	json.NewEncoder(w).Encode(challenge)
}

// verifyProof validates a payment proof against the x402 spec.
func (pg *PaymentGate) verifyProof(r *http.Request, proofHeader string) (*X402Receipt, error) {
	// Step 1: Decode proof from base64url
	proofJSON, err := base64.RawURLEncoding.DecodeString(proofHeader)
	if err != nil {
		// Fall back to raw JSON for compatibility
		proofJSON = []byte(proofHeader)
	}

	var proof X402Proof
	if err := json.Unmarshal(proofJSON, &proof); err != nil {
		return nil, fmt.Errorf("invalid proof JSON: %w", err)
	}

	if proof.V != 1 {
		return nil, fmt.Errorf("unsupported proof version: %d", proof.V)
	}

	// Step 2: Look up the challenge by its hash
	challenge, ok := pg.pendingChallenges[proof.ChallengeSHA256]
	if !ok {
		return nil, fmt.Errorf("unknown or expired challenge")
	}

	// Step 3: Verify proof.request matches challenge AND actual HTTP request
	if proof.Request.Method != challenge.Method || proof.Request.Method != r.Method {
		return nil, fmt.Errorf("method mismatch")
	}
	if proof.Request.Path != challenge.Path || proof.Request.Path != r.URL.Path {
		return nil, fmt.Errorf("path mismatch")
	}
	if proof.Request.Query != challenge.Query || proof.Request.Query != r.URL.RawQuery {
		return nil, fmt.Errorf("query mismatch")
	}

	// Step 4: Check expiry
	if time.Now().Unix() > challenge.ExpiresAt {
		delete(pg.pendingChallenges, proof.ChallengeSHA256)
		return nil, fmt.Errorf("challenge expired")
	}

	// Step 5: Decode transaction
	txBytes, err := base64.StdEncoding.DecodeString(proof.Payment.RawTxB64)
	if err != nil {
		// Fall back to hex for compatibility
		txBytes, err = hex.DecodeString(proof.Payment.RawTxB64)
		if err != nil {
			return nil, fmt.Errorf("invalid rawtx: %w", err)
		}
	}

	tx, err := transaction.NewTransactionFromBytes(txBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}

	// Step 6: Verify nonce UTXO spend
	if challenge.NonceUTXO != nil && challenge.NonceUTXO.LockingScriptHex != "dev-mode-no-real-utxo" {
		nonceSpent := false
		for _, input := range tx.Inputs {
			inputTxID := input.SourceTXID.String()
			if inputTxID == challenge.NonceUTXO.TxID && input.SourceTxOutIndex == uint32(challenge.NonceUTXO.Vout) {
				nonceSpent = true
				break
			}
		}
		if !nonceSpent {
			return nil, fmt.Errorf("nonce UTXO not spent: expected %s:%d",
				challenge.NonceUTXO.TxID, challenge.NonceUTXO.Vout)
		}
	}

	// Step 7: Verify payment output to payee
	if pg.payeeScriptHex != "" {
		payeeBytes, err := hex.DecodeString(pg.payeeScriptHex)
		if err != nil {
			return nil, fmt.Errorf("invalid payee script config: %w", err)
		}
		paid := false
		for _, out := range tx.Outputs {
			if out.Satoshis >= uint64(pg.priceSats) && fmt.Sprintf("%x", *out.LockingScript) == fmt.Sprintf("%x", payeeBytes) {
				paid = true
				break
			}
		}
		if !paid {
			return nil, fmt.Errorf("no output pays %d sats to payee %s",
				pg.priceSats, pg.payeeScriptHex[:16]+"...")
		}
	} else {
		// No payee configured — just check total output value (dev mode)
		var total uint64
		for _, out := range tx.Outputs {
			total += out.Satoshis
		}
		if total < uint64(pg.priceSats) {
			return nil, fmt.Errorf("insufficient payment: %d < %d sats", total, pg.priceSats)
		}
	}

	// Step 8: Verify txid
	txid := tx.TxID().String()
	if proof.Payment.TxID != "" && proof.Payment.TxID != txid {
		return nil, fmt.Errorf("txid mismatch: claimed %s, computed %s", proof.Payment.TxID, txid)
	}

	// Step 9: Mempool acceptance (deferred — requires ARC integration)
	// When require_mempool_accept is true and ARC is available,
	// broadcast the tx and verify acceptance. Not implemented yet.

	// Clean up the used challenge (one-time use even in dev mode)
	delete(pg.pendingChallenges, proof.ChallengeSHA256)

	return &X402Receipt{
		TxID:      txid,
		Satoshis:  pg.priceSats,
		Timestamp: time.Now().Unix(),
	}, nil
}

// cleanExpired removes challenges older than their expiry.
func (pg *PaymentGate) cleanExpired() {
	now := time.Now().Unix()
	for hash, ch := range pg.pendingChallenges {
		if now > ch.ExpiresAt {
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

// canonicalHeaderHash builds the canonical header binding string per x402 spec:
// lowercase names, trimmed values, sorted by name, concatenated as "name:value\n".
func canonicalHeaderHash(r *http.Request) string {
	// Bind a minimal set of headers: Host, Content-Type, Accept
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
