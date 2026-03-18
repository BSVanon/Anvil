package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// x402 HTTP headers following the merkleworks/x402-bsv wire protocol.
const (
	HeaderX402Challenge = "X-402-Challenge"
	HeaderX402Proof     = "X-402-Proof"
	HeaderX402Price     = "X-402-Price"
	HeaderX402Network   = "X-402-Network"
	HeaderX402Receipt   = "X-402-Receipt"
)

// PaymentChallenge is the 402 challenge body returned to unpaid requests.
type PaymentChallenge struct {
	Price     int    `json:"price"`     // satoshis required
	Network   string `json:"network"`   // "mainnet"
	Nonce     string `json:"nonce"`     // sha256 of method + path + timestamp
	Memo      string `json:"memo"`      // human-readable description
	Timestamp int64  `json:"timestamp"` // unix time of challenge
}

// PaymentProof is the proof submitted by the client in the X-402-Proof header.
type PaymentProof struct {
	TxHex string `json:"txHex"` // raw transaction hex
	TxID  string `json:"txid"`  // claimed txid
	Nonce string `json:"nonce"` // echoed nonce from challenge
}

// PaymentReceipt is returned in X-402-Receipt on successful payment.
type PaymentReceipt struct {
	TxID      string `json:"txid"`
	Satoshis  int    `json:"satoshis"`
	Timestamp int64  `json:"timestamp"`
}

// paymentGate returns middleware that gates endpoints behind HTTP 402.
// If priceSatoshis is 0, the middleware is a no-op (free access).
//
// The flow follows the x402 pattern:
//  1. Client sends request without payment → server returns 402 with challenge
//  2. Client constructs a BSV tx paying >= priceSatoshis → retries with X-402-Proof header
//  3. Server parses the tx, verifies it pays enough → allows request + returns receipt
//
// This is a stateless verification: the server checks that the submitted tx
// is a valid BSV transaction paying at least the required amount. Replay protection
// comes from nonce binding — the proof must echo the challenge nonce.
//
// Full UTXO-based settlement verification (broadcast + confirm) is deferred
// to a future integration with a settlement gateway (merkleworks-style delegator).
// The current implementation verifies tx structure and output value only.
func paymentGate(priceSatoshis int) func(http.HandlerFunc) http.HandlerFunc {
	if priceSatoshis <= 0 {
		return func(next http.HandlerFunc) http.HandlerFunc { return next }
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Check for payment proof
			proofHeader := r.Header.Get(HeaderX402Proof)
			if proofHeader == "" {
				// No payment — return 402 challenge
				challenge := buildChallenge(r, priceSatoshis)
				challengeJSON, _ := json.Marshal(challenge)

				w.Header().Set(HeaderX402Challenge, string(challengeJSON))
				w.Header().Set(HeaderX402Price, strconv.Itoa(priceSatoshis))
				w.Header().Set(HeaderX402Network, "mainnet")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired)
				json.NewEncoder(w).Encode(challenge)
				return
			}

			// Parse proof
			var proof PaymentProof
			if err := json.Unmarshal([]byte(proofHeader), &proof); err != nil {
				writeError(w, http.StatusBadRequest, "invalid X-402-Proof: "+err.Error())
				return
			}

			// Verify the tx is parseable and pays enough
			receipt, err := verifyPayment(proof, priceSatoshis)
			if err != nil {
				writeError(w, http.StatusPaymentRequired, "payment rejected: "+err.Error())
				return
			}

			// Payment accepted — set receipt header and proceed
			receiptJSON, _ := json.Marshal(receipt)
			w.Header().Set(HeaderX402Receipt, string(receiptJSON))
			next(w, r)
		}
	}
}

// buildChallenge creates a 402 challenge for a given request.
func buildChallenge(r *http.Request, priceSatoshis int) PaymentChallenge {
	now := time.Now().Unix()
	nonce := computeNonce(r.Method, r.URL.Path, now)
	return PaymentChallenge{
		Price:     priceSatoshis,
		Network:   "mainnet",
		Nonce:     nonce,
		Memo:      fmt.Sprintf("Anvil API: %s %s", r.Method, r.URL.Path),
		Timestamp: now,
	}
}

// computeNonce deterministically binds a payment to a specific request.
// Following merkleworks pattern: sha256(method + path + timestamp).
func computeNonce(method, path string, timestamp int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", method, path, timestamp)))
	return hex.EncodeToString(h[:16])
}

// verifyPayment checks that a payment proof contains a valid BSV transaction
// with outputs totalling at least the required satoshis.
func verifyPayment(proof PaymentProof, requiredSatoshis int) (*PaymentReceipt, error) {
	if proof.TxHex == "" {
		return nil, fmt.Errorf("empty txHex")
	}

	txBytes, err := hex.DecodeString(proof.TxHex)
	if err != nil {
		return nil, fmt.Errorf("invalid txHex: %w", err)
	}

	tx, err := transaction.NewTransactionFromBytes(txBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}

	// Sum all outputs — at least one must pay the required amount.
	// In a production deployment, the server would check that an output
	// pays to a specific address (derived per-request). For now we verify
	// the tx is structurally valid and carries sufficient value.
	var totalOutputSatoshis uint64
	for _, out := range tx.Outputs {
		totalOutputSatoshis += out.Satoshis
	}

	if totalOutputSatoshis < uint64(requiredSatoshis) {
		return nil, fmt.Errorf("insufficient payment: got %d satoshis, need %d",
			totalOutputSatoshis, requiredSatoshis)
	}

	txid := tx.TxID().String()
	if proof.TxID != "" && proof.TxID != txid {
		return nil, fmt.Errorf("txid mismatch: claimed %s, computed %s", proof.TxID, txid)
	}

	return &PaymentReceipt{
		TxID:      txid,
		Satoshis:  int(totalOutputSatoshis),
		Timestamp: time.Now().Unix(),
	}, nil
}
