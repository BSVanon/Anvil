package spv

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// gullibleTracker always says the merkle root is valid.
type gullibleTracker struct{}

func (g *gullibleTracker) IsValidRootForHeight(_ context.Context, _ *chainhash.Hash, _ uint32) (bool, error) {
	return true, nil
}
func (g *gullibleTracker) CurrentHeight(_ context.Context) (uint32, error) {
	return 999999, nil
}

// rejectTracker always says the merkle root is invalid.
type rejectTracker struct{}

func (r *rejectTracker) IsValidRootForHeight(_ context.Context, _ *chainhash.Hash, _ uint32) (bool, error) {
	return false, nil
}
func (r *rejectTracker) CurrentHeight(_ context.Context) (uint32, error) {
	return 999999, nil
}

// buildTestBEEFWithBUMP creates a BEEF binary containing a transaction with
// a merkle proof (BUMP). Uses the go-sdk to construct a structurally valid
// BEEF with a single-leaf merkle path.
func buildTestBEEFWithBUMP(t *testing.T) []byte {
	t.Helper()

	// Create a parent transaction (the "input source")
	parent := transaction.NewTransaction()
	parent.Version = 1
	parent.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: mustScript(t, "76a9140000000000000000000000000000000000000000ac"),
	})

	// Give the parent a merkle path (confirmed at block height 100)
	txidHash := parent.TxID()
	boolTrue := true
	parent.MerklePath = transaction.NewMerklePath(100, [][]*transaction.PathElement{
		{
			{Offset: 0, Hash: txidHash, Txid: &boolTrue},
			{Offset: 1, Duplicate: &boolTrue},
		},
	})

	// Create the child transaction that spends the parent
	child := transaction.NewTransaction()
	child.Version = 1
	child.AddInput(&transaction.TransactionInput{
		SourceTXID:        txidHash,
		SourceTxOutIndex:  0,
		SequenceNumber:    0xffffffff,
		SourceTransaction: parent,
	})
	child.AddOutput(&transaction.TransactionOutput{
		Satoshis:      900,
		LockingScript: mustScript(t, "76a9140000000000000000000000000000000000000000ac"),
	})

	beefBytes, err := child.BEEF()
	if err != nil {
		t.Fatalf("failed to encode BEEF: %v", err)
	}
	if len(beefBytes) == 0 {
		t.Fatal("BEEF encoding returned empty bytes")
	}
	return beefBytes
}

func mustScript(t *testing.T, hexStr string) *script.Script {
	t.Helper()
	s, err := script.NewFromHex(hexStr)
	if err != nil {
		t.Fatalf("invalid script hex: %v", err)
	}
	return s
}

// --- Invalid input ---

func TestValidateBEEFInvalidBytes(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	result, err := v.ValidateBEEF(context.Background(), []byte("not a beef"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("expected invalid for garbage bytes")
	}
	if result.Confidence != ConfidenceInvalid {
		t.Fatalf("expected confidence=invalid, got %s", result.Confidence)
	}
}

func TestValidateBEEFEmptyInput(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	result, err := v.ValidateBEEF(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("expected invalid for nil input")
	}
	if result.Confidence != ConfidenceInvalid {
		t.Fatalf("expected confidence=invalid, got %s", result.Confidence)
	}
}

// --- Confidence classification ---

func TestClassifyConfidenceAllVerified(t *testing.T) {
	c := classifyConfidence(3, 3, nil)
	if c != ConfidenceSPVVerified {
		t.Fatalf("expected spv_verified, got %s", c)
	}
}

func TestClassifyConfidencePartial(t *testing.T) {
	c := classifyConfidence(3, 1, nil)
	if c != ConfidencePartiallyVerified {
		t.Fatalf("expected partially_verified, got %s", c)
	}
}

func TestClassifyConfidenceNoBumps(t *testing.T) {
	c := classifyConfidence(0, 0, nil)
	if c != ConfidenceUnconfirmed {
		t.Fatalf("expected unconfirmed, got %s", c)
	}
}

func TestClassifyConfidenceBumpsButNoneVerified(t *testing.T) {
	c := classifyConfidence(2, 0, nil)
	if c != ConfidenceUnconfirmed {
		t.Fatalf("expected unconfirmed, got %s", c)
	}
}

func TestConfidenceMessages(t *testing.T) {
	cases := []struct {
		confidence string
		verified   int
		total      int
	}{
		{ConfidenceSPVVerified, 3, 3},
		{ConfidencePartiallyVerified, 1, 3},
		{ConfidenceUnconfirmed, 0, 0},
		{ConfidenceUnconfirmed, 0, 2},
		{ConfidenceInvalid, 0, 0},
	}
	for _, tc := range cases {
		msg := confidenceMessage(tc.confidence, tc.verified, tc.total)
		if msg == "" {
			t.Fatalf("expected non-empty message for %s", tc.confidence)
		}
	}
}

// --- Genuine BUMP-verified positive test ---
// Constructs a real BEEF with a merkle proof and validates it against
// a gullible tracker that accepts any root. This proves the full path:
// parse BEEF → find BUMPs → compute root → check against tracker → spv_verified.

func TestValidateBEEFWithBUMP_Positive(t *testing.T) {
	beefBytes := buildTestBEEFWithBUMP(t)

	v := NewValidator(&gullibleTracker{})
	result, err := v.ValidateBEEF(context.Background(), beefBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid, got invalid: %s", result.Message)
	}
	if result.TxID == "" {
		t.Fatal("expected non-empty txid")
	}
	if result.Confidence != ConfidenceSPVVerified {
		t.Fatalf("expected spv_verified, got %s: %s", result.Confidence, result.Message)
	}
	t.Logf("txid=%s confidence=%s message=%s", result.TxID, result.Confidence, result.Message)
}

// --- Genuine bad-proof rejection test ---
// Same BEEF, but the tracker rejects the merkle root. This proves that
// a structurally valid BEEF with proofs that don't match the header chain
// is correctly rejected.

func TestValidateBEEFWithBUMP_Rejected(t *testing.T) {
	beefBytes := buildTestBEEFWithBUMP(t)

	v := NewValidator(&rejectTracker{})
	result, err := v.ValidateBEEF(context.Background(), beefBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatal("expected invalid when tracker rejects root")
	}
	if result.Confidence != ConfidenceInvalid {
		t.Fatalf("expected confidence=invalid, got %s: %s", result.Confidence, result.Message)
	}
	t.Logf("correctly rejected: confidence=%s message=%s", result.Confidence, result.Message)
}

func TestValidatorCreation(t *testing.T) {
	v := NewValidator(&gullibleTracker{})
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestValidatorStatsTrackFailures(t *testing.T) {
	v := NewValidator(&gullibleTracker{})

	if _, err := v.ValidateBEEF(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	stats := v.Stats()
	if stats.Total != 1 || stats.Invalid != 1 {
		t.Fatalf("expected 1 invalid validation, got total=%d invalid=%d", stats.Total, stats.Invalid)
	}
	if stats.FailureByReason["empty_input"] != 1 {
		t.Fatalf("expected empty_input failure count, got %+v", stats.FailureByReason)
	}
}
