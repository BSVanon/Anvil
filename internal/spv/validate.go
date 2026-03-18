package spv

import (
	"context"
	"fmt"

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
}

// NewValidator creates an SPV validator backed by the given ChainTracker.
func NewValidator(tracker chaintracker.ChainTracker) *Validator {
	return &Validator{tracker: tracker}
}

// ValidateBEEF parses a BEEF binary and verifies all merkle proofs against
// the local header chain. Returns a confidence level based on the verification
// depth of the transaction ancestry.
//
// Confidence model (from architecture):
//   - spv_verified: all ancestors have merkle proofs verified against local headers
//   - partially_verified: some ancestors confirmed (SPV), some unconfirmed
//   - unconfirmed: top-level tx has no confirmed ancestors in this BEEF
//   - invalid: BEEF failed structural or proof validation
func (v *Validator) ValidateBEEF(ctx context.Context, beef []byte) (*Result, error) {
	if len(beef) == 0 {
		return &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    "empty BEEF input",
		}, nil
	}

	// Parse into full Beef structure to inspect all ancestry
	b, err := transaction.NewBeefFromBytes(beef)
	if err != nil {
		return &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    fmt.Sprintf("parse BEEF: %v", err),
		}, nil
	}

	// Also parse the final transaction for txid
	tx, err := transaction.NewTransactionFromBEEF(beef)
	if err != nil {
		return &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    fmt.Sprintf("parse transaction from BEEF: %v", err),
		}, nil
	}
	txid := tx.TxID().String()

	// Count BUMPs (merkle proofs) and verify each against header chain
	totalBumps := len(b.BUMPs)
	verifiedBumps := 0

	for _, bump := range b.BUMPs {
		if bump == nil {
			continue
		}
		// Each BUMP covers one or more transactions at a block height.
		// Walk the path elements to find txids and verify the root.
		if len(bump.Path) > 0 && len(bump.Path[0]) > 0 {
			// Compute root from first leaf txid
			for _, elem := range bump.Path[0] {
				if elem.Hash == nil {
					continue
				}
				root, err := bump.ComputeRoot(elem.Hash)
				if err != nil {
					continue
				}
				valid, err := v.tracker.IsValidRootForHeight(ctx, root, bump.BlockHeight)
				if err != nil {
					return &Result{
						Valid:      false,
						TxID:       txid,
						Confidence: ConfidenceInvalid,
						Message:    fmt.Sprintf("header lookup error at height %d: %v", bump.BlockHeight, err),
					}, nil
				}
				if valid {
					verifiedBumps++
				} else {
					return &Result{
						Valid:      false,
						TxID:       txid,
						Confidence: ConfidenceInvalid,
						Message:    fmt.Sprintf("merkle root mismatch at height %d", bump.BlockHeight),
					}, nil
				}
				break // one successful verification per BUMP is sufficient
			}
		}
	}

	// Determine confidence level
	confidence := classifyConfidence(totalBumps, verifiedBumps, tx)

	return &Result{
		Valid:      confidence != ConfidenceInvalid,
		TxID:       txid,
		Confidence: confidence,
		Message:    confidenceMessage(confidence, verifiedBumps, totalBumps),
	}, nil
}

// classifyConfidence determines the confidence level based on BUMP verification.
func classifyConfidence(totalBumps, verifiedBumps int, tx *transaction.Transaction) string {
	if totalBumps == 0 {
		// No BUMPs in the BEEF at all — fully unconfirmed
		return ConfidenceUnconfirmed
	}

	if verifiedBumps == totalBumps {
		return ConfidenceSPVVerified
	}

	if verifiedBumps > 0 {
		return ConfidencePartiallyVerified
	}

	// BUMPs present but none verified
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
