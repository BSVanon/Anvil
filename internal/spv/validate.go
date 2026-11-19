package spv

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/beefscan"
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
	// BEEF is what a caller stores or relays once the result is valid: the
	// BEEF validated, as beefnorm.BEEF.Bytes gives it, which is the bytes
	// received when they held nothing to drop and were already in canonical
	// form, and otherwise the kept BEEF in the format received.
	BEEF []byte `json:"-"`
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
// The BEEF is parsed only through beefnorm.Parse: beefscan prices its
// structure first, the parse is linear, and what Verify checks, what the
// confidence counts and what Result.BEEF holds is the subject and the
// ancestry its verification reads, with one canonical BUMP per block.
// Transactions outside that ancestry are dropped, not refused: see beefnorm
// for that divergence from BRC-95.
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

	n, err := safeParse(beef)
	if err != nil {
		result := &Result{Valid: false, Confidence: ConfidenceInvalid}
		reason := "parse_beef"
		switch {
		case errors.Is(err, beefscan.ErrTooComplex):
			// Priced before go-sdk parses it: its parse, Verify and
			// serializations are superlinear in some shapes and take no
			// context.
			result.Message, reason = fmt.Sprintf("%s: %v", beefscan.Code, err), "too_complex"
		case errors.Is(err, beefnorm.ErrRefused):
			result.Message, reason = fmt.Sprintf("refused BEEF: %v", err), "refused"
		case errors.Is(err, beefnorm.ErrNoSubject):
			result.Message, reason = fmt.Sprintf("parse transaction from BEEF: %v", err), "parse_transaction"
		default:
			result.Message = fmt.Sprintf("parse BEEF: %v", err)
		}
		v.recordResult(result, reason)
		return result, nil
	}
	// Callers store and relay what this accepts with NewTransactionFromBEEF,
	// which reads V1 and Atomic BEEFs only, so a V2 BEEF has always been
	// refused here; inside an Atomic BEEF it is accepted.
	if n.Format == transaction.BEEF_V2 {
		result := &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    "parse transaction from BEEF: a V2 BEEF is accepted only inside an Atomic BEEF",
		}
		v.recordResult(result, "parse_transaction")
		return result, nil
	}
	normalized, err := n.Bytes()
	if err != nil {
		result := &Result{
			Valid:      false,
			Confidence: ConfidenceInvalid,
			Message:    fmt.Sprintf("serialize BEEF: %v", err),
		}
		v.recordResult(result, "parse_beef")
		return result, nil
	}
	txid := n.Subject.String()

	if len(n.Beef.BUMPs) == 0 {
		// No merkle proofs at all — fully unconfirmed
		result := &Result{
			Valid:      true,
			TxID:       txid,
			Confidence: ConfidenceUnconfirmed,
			Message:    "no merkle proofs in BEEF — fully unconfirmed ancestry",
			BEEF:       normalized,
		}
		v.recordResult(result, "")
		return result, nil
	}

	// Use go-sdk's Beef.Verify() — it walks all BUMPs, computes roots,
	// and checks each against our ChainTracker. One call, no manual
	// path walking.
	valid, err := n.Beef.Verify(ctx, v.tracker, false)
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

	// All BUMPs verified. Classify confidence by how much of the kept
	// ancestry is proven: beefnorm keeps one BUMP per block, so proofs are
	// counted by the transactions they prove, not by BUMPs.
	ancestors, proven := len(n.Beef.Transactions)-1, 0
	for _, e := range n.Beef.Transactions {
		if e.DataFormat == transaction.RawTxAndBumpIndex {
			proven++
		}
	}
	if proven >= ancestors {
		// Every ancestor kept has a proof (or the subject has its own).
		result := &Result{
			Valid:      true,
			TxID:       txid,
			Confidence: ConfidenceSPVVerified,
			Message:    fmt.Sprintf("all %d merkle proofs verified against local headers", proven),
			BEEF:       normalized,
		}
		v.recordResult(result, "")
		return result, nil
	}

	// Some txs in the ancestry lack proofs
	result := &Result{
		Valid:      true,
		TxID:       txid,
		Confidence: ConfidencePartiallyVerified,
		Message:    fmt.Sprintf("%d merkle proofs verified, %d ancestor txs unconfirmed", proven, ancestors-proven),
		BEEF:       normalized,
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

// safeParse is beefnorm.Parse behind a panic recover. go-sdk's BEEF parsers
// indexed and allocated from attacker-controlled length fields without bounds
// checks on some paths before v1.7.7 (a body starting with the Atomic marker
// but shorter than 36 bytes, an oversized varint count). On the public
// /broadcast ingress path an unguarded panic crashes the request goroutine
// and the TLS front returns 502; the caller must instead get a clean
// ConfidenceInvalid. beefnorm recovers its own normalization's panics.
func safeParse(beef []byte) (n *beefnorm.BEEF, err error) {
	defer func() {
		if r := recover(); r != nil {
			n = nil
			err = fmt.Errorf("BEEF parse panicked: %v", r)
		}
	}()
	return parseBEEF(beef)
}

// parseBEEF is the parse safeParse guards. go-sdk v1.7.7 bounds the reads
// that panicked in v1.2.x, and beefscan refuses the malformed shapes first,
// so no known input reaches the recover now; it is a variable so a test can
// make it panic.
var parseBEEF = beefnorm.Parse
