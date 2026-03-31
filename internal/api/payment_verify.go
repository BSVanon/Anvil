package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// verifyProof validates a payment proof against the x402 spec.
func (pg *PaymentGate) verifyProof(r *http.Request, proofHeader string) (*X402Receipt, error) {
	// Step 1: Decode proof from base64url
	proofJSON, err := base64.RawURLEncoding.DecodeString(proofHeader)
	if err != nil {
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
	pg.mu.Lock()
	pending, ok := pg.pendingChallenges[proof.ChallengeSHA256]
	pg.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown or expired challenge")
	}
	challenge := pending.challenge
	payees := pending.payees

	// Step 3: Three-way request binding verification
	if proof.Request.Method != challenge.Method || proof.Request.Method != r.Method {
		return nil, fmt.Errorf("method mismatch")
	}
	if proof.Request.Path != challenge.Path || proof.Request.Path != r.URL.Path {
		return nil, fmt.Errorf("path mismatch")
	}
	if proof.Request.Query != challenge.Query || proof.Request.Query != r.URL.RawQuery {
		return nil, fmt.Errorf("query mismatch")
	}

	liveHeaderHash := canonicalHeaderHash(r)
	liveBodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	liveBodyHash := sha256Hex(liveBodyBytes)
	// Restore the body so downstream handlers (e.g. POST /data) can read it.
	r.Body = io.NopCloser(bytes.NewReader(liveBodyBytes))

	if proof.Request.ReqHeadersSHA256 != challenge.ReqHeadersSHA256 {
		return nil, fmt.Errorf("req_headers_sha256: proof does not match challenge")
	}
	if challenge.ReqHeadersSHA256 != liveHeaderHash {
		return nil, fmt.Errorf("req_headers_sha256: challenge does not match live request")
	}
	if proof.Request.ReqBodySHA256 != challenge.ReqBodySHA256 {
		return nil, fmt.Errorf("req_body_sha256: proof does not match challenge")
	}
	if challenge.ReqBodySHA256 != liveBodyHash {
		return nil, fmt.Errorf("req_body_sha256: challenge does not match live request")
	}

	// Step 4: Check expiry
	if time.Now().Unix() > challenge.ExpiresAt {
		pg.mu.Lock()
		delete(pg.pendingChallenges, proof.ChallengeSHA256)
		pg.mu.Unlock()
		return nil, fmt.Errorf("challenge expired")
	}

	// Step 5: Decode transaction
	txBytes, err := base64.StdEncoding.DecodeString(proof.Payment.RawTxB64)
	if err != nil {
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
			if challenge.NonceUTXO.Vout >= 0 && inputTxID == challenge.NonceUTXO.TxID && input.SourceTxOutIndex == uint32(challenge.NonceUTXO.Vout) { // #nosec G115 // guarded by >= 0 check
				nonceSpent = true
				break
			}
		}
		if !nonceSpent {
			return nil, fmt.Errorf("nonce UTXO not spent: expected %s:%d",
				challenge.NonceUTXO.TxID, challenge.NonceUTXO.Vout)
		}
	}

	// Step 6b: Verify nonce input signature (script execution).
	// This prevents forged transactions that claim to spend the nonce UTXO
	// but have invalid signatures. Without this, an attacker could construct
	// a tx with correct outputs but fake input signatures and get served data.
	if challenge.NonceUTXO != nil && challenge.NonceUTXO.LockingScriptHex != "dev-mode-no-real-utxo" {
		if err := verifyNonceInputSignature(tx, challenge.NonceUTXO); err != nil {
			return nil, fmt.Errorf("nonce input signature invalid: %w", err)
		}
	}

	// Step 7: Verify ALL payees are paid.
	totalPaid := 0
	for _, payee := range payees {
		payeeBytes, err := hex.DecodeString(payee.LockingScriptHex)
		if err != nil {
			return nil, fmt.Errorf("invalid payee script (%s): %w", payee.Role, err)
		}
		found := false
		for _, out := range tx.Outputs {
			if payee.AmountSats >= 0 && out.Satoshis >= uint64(payee.AmountSats) && fmt.Sprintf("%x", *out.LockingScript) == fmt.Sprintf("%x", payeeBytes) {
				found = true
				totalPaid += payee.AmountSats
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no output pays %d sats to %s payee", payee.AmountSats, payee.Role)
		}
	}

	// Step 8: Verify txid
	txid := tx.TxID().String()
	if proof.Payment.TxID != "" && proof.Payment.TxID != txid {
		return nil, fmt.Errorf("txid mismatch: claimed %s, computed %s", proof.Payment.TxID, txid)
	}

	// Step 9: Mempool acceptance via ARC.
	// When requireMempool is true AND an ARC client is available,
	// broadcast the proof tx and require SEEN_ON_NETWORK before accepting.
	// This prevents attackers from submitting structurally valid but
	// never-broadcast transactions.
	if challenge.RequireMempoolAccept && pg.arcClient != nil {
		arcResp, err := pg.arcClient.Submit(txBytes)
		if err != nil {
			return nil, fmt.Errorf("ARC broadcast failed: %w", err)
		}
		// Accept SEEN_ON_NETWORK, MINED, or any success status
		switch arcResp.Status {
		case "SEEN_ON_NETWORK", "MINED", "SEEN_IN_ORPHAN_MEMPOOL":
			// OK — miner has it
		default:
			return nil, fmt.Errorf("ARC rejected payment tx: status=%s", arcResp.Status)
		}
	}

	// Clean up the used challenge (one-time use)
	pg.mu.Lock()
	delete(pg.pendingChallenges, proof.ChallengeSHA256)
	pg.mu.Unlock()

	return &X402Receipt{
		TxID:      txid,
		Satoshis:  totalPaid,
		Timestamp: time.Now().Unix(),
	}, nil
}

// verifyNonceInputSignature runs the BSV script interpreter to verify that
// the input spending the nonce UTXO has a valid signature. This catches
// forged transactions where the outputs are correct but the input signature
// is invalid (meaning the tx would be rejected by miners).
func verifyNonceInputSignature(tx *transaction.Transaction, nonce *NonceUTXO) error {
	// Find the input that spends the nonce UTXO
	inputIdx := -1
	for i, input := range tx.Inputs {
		if input.SourceTXID != nil && input.SourceTXID.String() == nonce.TxID &&
			nonce.Vout >= 0 && input.SourceTxOutIndex == uint32(nonce.Vout) { // #nosec G115 // guarded
			inputIdx = i
			break
		}
	}
	if inputIdx < 0 {
		return fmt.Errorf("nonce input not found in transaction")
	}

	// Decode the nonce UTXO's locking script
	lockingBytes, err := hex.DecodeString(nonce.LockingScriptHex)
	if err != nil {
		return fmt.Errorf("invalid nonce locking script hex: %w", err)
	}
	lockingScript := bsvscript.Script(lockingBytes)

	input := tx.Inputs[inputIdx]
	if input.UnlockingScript == nil || len(*input.UnlockingScript) == 0 {
		return fmt.Errorf("nonce input has no unlocking script")
	}

	// Run the script interpreter: unlocking + locking script
	if nonce.Satoshis < 0 {
		return fmt.Errorf("nonce UTXO has negative satoshis: %d", nonce.Satoshis)
	}
	engine := interpreter.NewEngine()
	err = engine.Execute(
		interpreter.WithTx(tx, inputIdx, &transaction.TransactionOutput{
			LockingScript: &lockingScript,
			Satoshis:      uint64(nonce.Satoshis), // #nosec G115 // guarded by < 0 check above
		}),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
		interpreter.WithScripts(&lockingScript, input.UnlockingScript),
	)
	if err != nil {
		return fmt.Errorf("script execution failed: %w", err)
	}

	return nil
}

// verifyDirectPayment handles the x-bsv-payment header format.
// Accepts a raw BSV transaction (hex or base64) and verifies it pays the
// declared payees. No challenge-nonce binding — simpler but less
// replay-resistant than the full x402 challenge-proof flow.
func (pg *PaymentGate) verifyDirectPayment(paymentHeader string, payees []Payee) (*X402Receipt, error) {
	paymentHeader = strings.TrimSpace(paymentHeader)
	if paymentHeader == "" {
		return nil, fmt.Errorf("empty payment header")
	}

	// Try to decode: hex first (most common), then base64
	txBytes, err := hex.DecodeString(paymentHeader)
	if err != nil {
		txBytes, err = base64.StdEncoding.DecodeString(paymentHeader)
		if err != nil {
			txBytes, err = base64.RawStdEncoding.DecodeString(paymentHeader)
			if err != nil {
				return nil, fmt.Errorf("cannot decode payment: not valid hex or base64")
			}
		}
	}

	tx, err := transaction.NewTransactionFromBytes(txBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction in payment header: %w", err)
	}

	// Verify all payees are paid (same logic as challenge-proof path)
	totalPaid := 0
	for _, payee := range payees {
		payeeBytes, err := hex.DecodeString(payee.LockingScriptHex)
		if err != nil {
			return nil, fmt.Errorf("invalid payee script (%s): %w", payee.Role, err)
		}
		found := false
		for _, out := range tx.Outputs {
			if payee.AmountSats >= 0 && out.Satoshis >= uint64(payee.AmountSats) && fmt.Sprintf("%x", *out.LockingScript) == fmt.Sprintf("%x", payeeBytes) {
				found = true
				totalPaid += payee.AmountSats
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no output pays %d sats to %s payee", payee.AmountSats, payee.Role)
		}
	}

	txid := tx.TxID().String()

	// Broadcast to ARC if available (direct payments aren't challenge-bound,
	// so mempool acceptance is important for settlement assurance)
	if pg.arcClient != nil {
		arcResp, err := pg.arcClient.Submit(txBytes)
		if err != nil {
			return nil, fmt.Errorf("ARC broadcast failed: %w", err)
		}
		switch arcResp.Status {
		case "SEEN_ON_NETWORK", "MINED", "SEEN_IN_ORPHAN_MEMPOOL":
			// OK
		default:
			return nil, fmt.Errorf("ARC rejected payment tx: status=%s", arcResp.Status)
		}
	}

	return &X402Receipt{
		TxID:      txid,
		Satoshis:  totalPaid,
		Timestamp: time.Now().Unix(),
	}, nil
}
