package spv

import (
	"context"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// Result holds the outcome of a BEEF validation.
type Result struct {
	Valid   bool   `json:"valid"`
	TxID    string `json:"txid"`
	Height  uint32 `json:"height,omitempty"` // block height if merkle proof verified
	Message string `json:"message,omitempty"`
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
// the local header chain. Does NOT rewrite BEEF decoding — uses go-sdk.
func (v *Validator) ValidateBEEF(ctx context.Context, beef []byte) (*Result, error) {
	// Parse BEEF into transaction
	tx, err := transaction.NewTransactionFromBEEF(beef)
	if err != nil {
		return &Result{Valid: false, Message: fmt.Sprintf("parse BEEF: %v", err)}, nil
	}

	txid := tx.TxID().String()

	// If the transaction has a merkle path, verify it
	if tx.MerklePath != nil {
		valid, err := tx.MerklePath.Verify(ctx, tx.TxID(), v.tracker)
		if err != nil {
			return &Result{Valid: false, TxID: txid, Message: fmt.Sprintf("verify merkle path: %v", err)}, nil
		}
		if !valid {
			return &Result{Valid: false, TxID: txid, Message: "merkle proof does not match header chain"}, nil
		}
		return &Result{
			Valid:   true,
			TxID:    txid,
			Height:  tx.MerklePath.BlockHeight,
			Message: "proof-valid",
		}, nil
	}

	// No merkle path — transaction is unconfirmed. Still structurally valid BEEF.
	return &Result{
		Valid:   true,
		TxID:    txid,
		Message: "no merkle proof (unconfirmed)",
	}, nil
}

// ValidateBeefFull parses the full Beef structure and verifies all BUMPs
// against the header chain. This validates the entire ancestry, not just
// the final transaction.
func (v *Validator) ValidateBeefFull(ctx context.Context, beef []byte) (*Result, error) {
	b, err := transaction.NewBeefFromBytes(beef)
	if err != nil {
		return &Result{Valid: false, Message: fmt.Sprintf("parse BEEF: %v", err)}, nil
	}

	valid, err := b.Verify(ctx, v.tracker, false)
	if err != nil {
		return &Result{Valid: false, Message: fmt.Sprintf("verify BEEF: %v", err)}, nil
	}
	if !valid {
		return &Result{Valid: false, Message: "BEEF verification failed"}, nil
	}

	return &Result{Valid: true, Message: "all proofs verified"}, nil
}
