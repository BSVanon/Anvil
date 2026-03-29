package spv

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// Confidence levels for BEEF validation, per architecture contract.
const (
	// All ancestors have merkle proofs verified against local headers.
	ConfidenceSPVVerified = "spv_verified"
	// Some ancestors confirmed (SPV), some unconfirmed (0-conf scripts valid).
	ConfidencePartiallyVerified = "partially_verified"
	// Top-level tx has no confirmed ancestors in this BEEF.
	ConfidenceUnconfirmed = "unconfirmed"
	// BEEF failed structural or proof validation.
	ConfidenceInvalid = "invalid"
)

// Result holds the outcome of a BEEF validation.
type Result struct {
	Valid      bool   `json:"valid"`
	TxID       string `json:"txid,omitempty"`
	Confidence string `json:"confidence"`
	Message    string `json:"message,omitempty"`
}

// Validator verifies BEEF-encoded transactions against a local header chain.
type Validator struct {
	tracker chaintracker.ChainTracker

	mu    sync.Mutex
	stats ValidationStats
}

// ValidationStats captures operator-visible SPV verification metrics.
type ValidationStats struct {
	Total           int64            `json:"total"`
	Valid           int64            `json:"valid"`
	Invalid         int64            `json:"invalid"`
	LastValidatedAt string           `json:"last_validated_at,omitempty"`
	LastError       string           `json:"last_error,omitempty"`
	ByConfidence    map[string]int64 `json:"by_confidence,omitempty"`
	FailureByReason map[string]int64 `json:"failure_by_reason,omitempty"`
}

// NewValidator creates an SPV validator backed by the given ChainTracker.
func NewValidator(tracker chaintracker.ChainTracker) *Validator {
	return &Validator{
		tracker: tracker,
		stats: ValidationStats{
			ByConfidence:    make(map[string]int64),
			FailureByReason: make(map[string]int64),
		},
	}
}

// ValidateBEEF parses a BEEF binary and verifies all merkle proofs against
// the local header chain using go-sdk's Beef.Verify(). Returns a confidence
// level based on the verification depth of the transaction ancestry.
//
// Confidence model (from architecture):
//   - spv_verified: all ancestors have merkle proofs verified against local headers
//   - partially_verified: some ancestors confirmed (SPV), some unconfirmed
//   - unconfirmed: top-level tx has no confirmed ancestors in this BEEF
//   - invalid: BEEF failed structural or proof validation
func (v *Validator) ValidateBEEF(ctx context.Context, beef []byte) (*Result, error) {
	if len(beef) == 0 {
		result := &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    "empty BEEF input",
		}
		v.recordResult(result, "empty_input")
		return result, nil
	}

	// Parse the full Beef structure — go-sdk handles all BEEF versions
	b, err := transaction.NewBeefFromBytes(beef)
	if err != nil {
		result := &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    fmt.Sprintf("parse BEEF: %v", err),
		}
		v.recordResult(result, "parse_beef")
		return result, nil
	}

	// Parse the final transaction for its txid
	tx, err := transaction.NewTransactionFromBEEF(beef)
	if err != nil {
		result := &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    fmt.Sprintf("parse transaction from BEEF: %v", err),
		}
		v.recordResult(result, "parse_transaction")
		return result, nil
	}
	txid := tx.TxID().String()

	totalBumps := len(b.BUMPs)

	if totalBumps == 0 {
		// No merkle proofs at all — fully unconfirmed
		result := &Result{
			Valid:      true,
			TxID:       txid,
			Confidence: ConfidenceUnconfirmed,
			Message:    "no merkle proofs in BEEF — fully unconfirmed ancestry",
		}
		v.recordResult(result, "")
		return result, nil
	}

	// Use go-sdk's Beef.Verify() — it walks all BUMPs, computes roots,
	// and checks each against our ChainTracker. One call, no manual
	// path walking.
	valid, err := b.Verify(ctx, v.tracker, false)
	if err != nil {
		result := &Result{
			Valid:      false,
			TxID:       txid,
			Confidence: ConfidenceInvalid,
			Message:    fmt.Sprintf("BEEF verification: %v", err),
		}
		v.recordResult(result, "verify_error")
		return result, nil
	}

	if !valid {
		result := &Result{
			Valid:      false,
			TxID:       txid,
			Confidence: ConfidenceInvalid,
			Message:    "merkle proofs did not verify against local header chain",
		}
		v.recordResult(result, "root_mismatch")
		return result, nil
	}

	// All BUMPs verified. Classify confidence by how much of the
	// ancestry is proven.
	totalTxs := len(b.Transactions)
	if totalBumps >= totalTxs-1 {
		// All ancestor txs have proofs (minus the top-level unconfirmed tx)
		result := &Result{
			Valid:      true,
			TxID:       txid,
			Confidence: ConfidenceSPVVerified,
			Message:    fmt.Sprintf("all %d merkle proofs verified against local headers", totalBumps),
		}
		v.recordResult(result, "")
		return result, nil
	}

	// Some txs in the ancestry lack proofs
	result := &Result{
		Valid:      true,
		TxID:       txid,
		Confidence: ConfidencePartiallyVerified,
		Message:    fmt.Sprintf("%d merkle proofs verified, %d ancestor txs unconfirmed", totalBumps, totalTxs-1-totalBumps),
	}
	v.recordResult(result, "")
	return result, nil
}

func (v *Validator) Stats() ValidationStats {
	v.mu.Lock()
	defer v.mu.Unlock()

	stats := v.stats
	stats.ByConfidence = cloneCountMap(v.stats.ByConfidence)
	stats.FailureByReason = cloneCountMap(v.stats.FailureByReason)
	return stats
}

func (v *Validator) recordResult(result *Result, failureReason string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.stats.Total++
	v.stats.LastValidatedAt = time.Now().UTC().Format(time.RFC3339)
	v.stats.ByConfidence[result.Confidence]++
	if result.Valid {
		v.stats.Valid++
		v.stats.LastError = ""
		return
	}

	v.stats.Invalid++
	v.stats.LastError = result.Message
	if failureReason != "" {
		v.stats.FailureByReason[failureReason]++
	}
}

func cloneCountMap(in map[string]int64) map[string]int64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// classifyConfidence is used by tests to verify the classification logic
// independently of BEEF parsing.
func classifyConfidence(totalBumps, verifiedBumps int, tx *transaction.Transaction) string {
	if totalBumps == 0 {
		return ConfidenceUnconfirmed
	}
	if verifiedBumps == totalBumps {
		return ConfidenceSPVVerified
	}
	if verifiedBumps > 0 {
		return ConfidencePartiallyVerified
	}
	return ConfidenceUnconfirmed
}

func confidenceMessage(confidence string, verified, total int) string {
	switch confidence {
	case ConfidenceSPVVerified:
		return fmt.Sprintf("all %d merkle proofs verified against local headers", verified)
	case ConfidencePartiallyVerified:
		return fmt.Sprintf("%d of %d merkle proofs verified, remainder unconfirmed", verified, total)
	case ConfidenceUnconfirmed:
		if total == 0 {
			return "no merkle proofs in BEEF — fully unconfirmed ancestry"
		}
		return "merkle proofs present but could not be verified"
	case ConfidenceInvalid:
		return "BEEF validation failed"
	default:
		return ""
	}
}
