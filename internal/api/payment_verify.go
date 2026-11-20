package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// verifyProof validates a payment proof against the x402 spec.
func (pg *PaymentGate) verifyProof(w http.ResponseWriter, r *http.Request, proofHeader string) (receipt *X402Receipt, err error) {
	// Step 0: Refuse an oversized header before decoding it (payment_bounds.go).
	if err := checkPaymentHeaderSize(HeaderX402Proof, proofHeader); err != nil {
		return nil, err
	}

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
	// Read under the payment-body bounds (payment_bodyread.go), which also
	// leaves the body readable for the handler after the gate (e.g. POST /data).
	liveBodyBytes, err := readPaymentBody(w, r)
	if err != nil {
		return nil, err
	}
	liveBodyHash := sha256Hex(liveBodyBytes)

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

	// Step 4b: Count this proof against the challenge (payment_bounds.go). The
	// checks above are cheap; the steps below decode the transaction and run
	// the nonce input's scripts. The challenge is removed once a proof passes
	// or its last attempt fails.
	if err := pg.reserveProofAttempt(proof.ChallengeSHA256, pending); err != nil {
		return nil, err
	}
	defer func() { pg.endProofAttempt(proof.ChallengeSHA256, pending, err == nil) }()

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
	// When requireMempool is true AND an ARC client is available, broadcast
	// the proof tx and require a status that shows the network accepted it
	// (arcAccepted, payment_arc.go). This prevents attackers from submitting
	// structurally valid but never-broadcast transactions.
	if challenge.RequireMempoolAccept && pg.arcClient != nil {
		arcResp, err := pg.arcClient.Submit(txBytes)
		if err != nil {
			return nil, fmt.Errorf("ARC broadcast failed: %w", err)
		}
		if err := checkARCAcceptance(arcResp); err != nil {
			return nil, err
		}
	}

	// The deferred endProofAttempt removes the used challenge (one-time use).
	return &X402Receipt{
		TxID:      txid,
		Satoshis:  totalPaid,
		Timestamp: time.Now().Unix(),
		outputs:   paidOutputs(tx),
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
	// Refuse anything that cannot be a P2PKH spend before the interpreter
	// sees it (payment_bounds.go).
	if err := checkNonceUnlockingScript(&lockingScript, input.UnlockingScript); err != nil {
		return fmt.Errorf("nonce input: %w", err)
	}

	// Run the script interpreter: unlocking + locking script, under the
	// flags and deadline in payment_bounds.go.
	if nonce.Satoshis < 0 {
		return fmt.Errorf("nonce UTXO has negative satoshis: %d", nonce.Satoshis)
	}
	err = runNonceScripts(tx, inputIdx, &transaction.TransactionOutput{
		LockingScript: &lockingScript,
		Satoshis:      uint64(nonce.Satoshis), // #nosec G115 // guarded by < 0 check above
	})
	if err != nil {
		return fmt.Errorf("script execution failed: %w", err)
	}

	return nil
}

// verifyDirectPayment handles the X-Bsv-Payment header: an Extended Format
// (BRC-30) transaction, as hex or base64, that pays the declared payees, with
// no challenge binding. It needs ARC: a node with no ARC client refuses every
// direct payment (errDirectPaymentUnavailable, payment_refusal.go).
func (pg *PaymentGate) verifyDirectPayment(paymentHeader string, payees []Payee) (*X402Receipt, error) {
	if pg.arcClient == nil {
		return nil, errDirectPaymentUnavailable
	}
	// Refuse an oversized header before decoding it (payment_bounds.go).
	if err := checkPaymentHeaderSize(HeaderBSVPayment, paymentHeader); err != nil {
		return nil, err
	}
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

	// One transaction pays for one request (payment_replay.go). The claim is
	// released on every return, and kept only for an accepted payment.
	txHash := tx.TxID()
	txid := txHash.String()
	if !pg.replays.begin(*txHash) {
		return nil, &paymentRefusal{code: codePaymentReplayed,
			msg: "payment transaction " + txid + " was already used: a direct payment pays for one request"}
	}
	accepted := false
	defer func() { pg.replays.end(*txHash, accepted) }()

	// Verify every input's script and signature against the source output the
	// client supplied (payment_direct_verify.go), before ARC is asked. The
	// check proves the signatures match those outputs, not that the outputs
	// exist; ARC's answer below is what shows that.
	if err := verifyDirectPaymentInputs(tx); err != nil {
		return nil, fmt.Errorf("direct payment input verification failed: %w", err)
	}

	// Broadcast the payment: a direct payment has no challenge binding, so
	// only the network's acceptance shows that its inputs exist and are
	// unspent.
	arcResp, err := pg.arcClient.Submit(txBytes)
	if err != nil {
		return nil, fmt.Errorf("ARC broadcast failed: %w", err)
	}
	if err := checkARCAcceptance(arcResp); err != nil {
		return nil, err
	}
	if err := pg.checkPaymentDepth(arcResp); err != nil {
		return nil, err
	}
	accepted = true

	return &X402Receipt{
		TxID:      txid,
		Satoshis:  totalPaid,
		Timestamp: time.Now().Unix(),
		outputs:   paidOutputs(tx),
	}, nil
}
