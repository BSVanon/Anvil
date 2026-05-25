package topics

// Canonical upstream primitive — UMP (User Management Protocol).
//
// **Hosted in Anvil today as a pragmatic transitional placement**; the
// long-term home is `bsv-blockchain/go-overlay-discovery-services` once
// that repo gains a topic-impl partition for non-SHIP/SLAP canonical
// primitives. To be PR'd upstream when that home exists; this file
// becomes a one-line re-export at that point.
//
// Port source: `bsv-blockchain/overlay-express-examples` →
// `ts-stack/packages/overlays/topics/src/ump/UMPTopicManager.ts` (commit
// pinned via the MCP go-stack source). Behavior preserved 1:1 modulo
// language idioms; admission rules + v3 detection + kdfAlgorithm
// validation mirror the canonical TypeScript implementation.
//
// SendBSV-Wallet consumes this topic to publish cross-device-recovery
// UMP tokens (12-field PushDrop carrying encrypted recovery primaries +
// password salts). Anvil's job is admission-only: PushDrop-decode the
// output, verify field count + v3-version invariants, and admit. The
// wallet does ALL encrypt/decrypt/derive client-side — Anvil sees only
// opaque bytes plus the lookup keys (presentationHash, recoveryHash) it
// indexes for query.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
)

// UMPTopicName is the BRC-87 canonical name for the User Management
// Protocol topic. Wallets publish UMP tokens (1-sat PushDrop outputs)
// under this topic.
const UMPTopicName = "tm_users"

// UMPMinFields is the minimum required PushDrop field count for any
// UMP token version. v1 + v2 tokens have exactly 11 fields (indices
// 0-10); v3 tokens add umpVersion + kdfAlgorithm + kdfParams (indices
// 11-13 or 12-14 depending on field layout).
const UMPMinFields = 11

// UMP v3 supported KDF algorithms. Anything else is rejected at
// admission per the canonical TS impl.
const (
	UMPKDFArgon2id       = "argon2id"
	UMPKDFPBKDF2SHA512   = "pbkdf2-sha512"
	UMPVersionV3FieldLen = 1 // single-byte version field signals v3 candidacy
	UMPVersionV3         = 3 // expected umpVersion byte value
)

// UMPEntry is the metadata Anvil stores on each admitted UMP output.
// Lookup keys (presentationHash, recoveryHash) come from canonical
// PushDrop field indices 6 + 7 per UMPLookupService.ts:23-24.
type UMPEntry struct {
	// PresentationHash is the hex-encoded canonical lookup key for
	// "returning user, same passkey" rehydration. Comes from field[6].
	PresentationHash string `json:"presentation_hash"`
	// RecoveryHash is the hex-encoded canonical lookup key for
	// "lost passkey, recovery via recovery key" restore. From field[7].
	RecoveryHash string `json:"recovery_hash"`
	// UMPVersion is 0 for v1/v2 tokens, 3 for v3. Determined by the
	// presence of a 1-byte version field at index 11 or 12.
	UMPVersion uint8 `json:"ump_version,omitempty"`
	// KDFAlgorithm is the key-derivation-function name for v3 tokens
	// ("argon2id" or "pbkdf2-sha512"). Empty for v1/v2.
	KDFAlgorithm string `json:"kdf_algorithm,omitempty"`
	// KDFIterations is the configured iteration count parsed from the
	// v3 kdfParams JSON. Zero for v1/v2 or malformed v3 params.
	KDFIterations uint32 `json:"kdf_iterations,omitempty"`
}

// UMPTopicManager admits UMP token outputs into the tm_users topic.
//
// Admission contract (matches UMPTopicManager.ts:5-69):
//
//  1. Decode each output's locking script via canonical PushDrop.
//  2. Require >= UMPMinFields fields.
//  3. If the field count + length pattern signals a v3 token, validate:
//     - umpVersion field byte must equal 3
//     - kdfAlgorithm must be "argon2id" or "pbkdf2-sha512"
//     - kdfParams must be valid JSON with positive iterations
//  4. Admit the output index. Per-output errors are logged via the
//     metadata channel and the output is silently skipped — matches
//     TS console.warn behavior.
//
// Anvil does NOT decrypt UMP fields. Field[6] (presentationHash) and
// field[7] (recoveryHash) are stored in the lookup index as opaque hex
// strings; the wallet's encrypted primaries (fields 1-5, 8-10, 11) stay
// opaque to Anvil entirely.
type UMPTopicManager struct{}

// NewUMPTopicManager constructs a UMP topic manager. Stateless;
// safe to call once at v3engine.New time.
func NewUMPTopicManager() *UMPTopicManager {
	return &UMPTopicManager{}
}

// Admit evaluates a transaction for UMP token outputs.
func (m *UMPTopicManager) Admit(txData []byte, previousUTXOs []anviloverlay.AdmittedOutput) (*anviloverlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("ump: invalid transaction: %w", err)
	}

	var outputsToAdmit []int
	var coinsRemoved []int
	outputMetadata := make(map[int]json.RawMessage)

	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		entry, err := ParseUMPOutput(out.LockingScript.Bytes())
		if err != nil || entry == nil {
			// Per TS impl, malformed outputs are silently skipped.
			continue
		}
		outputsToAdmit = append(outputsToAdmit, i)
		if meta, err := json.Marshal(entry); err == nil {
			outputMetadata[i] = meta
		}
	}

	// UMP tokens are spent-by-overwrite: the wallet creates a new token
	// each time anchors update, spending the previous one. Mark all
	// previously-admitted UTXOs as removed.
	for i := range previousUTXOs {
		coinsRemoved = append(coinsRemoved, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsRemoved) == 0 {
		return nil, nil
	}

	return &anviloverlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  nil,
		CoinsRemoved:   coinsRemoved,
		OutputMetadata: outputMetadata,
	}, nil
}

// GetDocumentation returns the human-readable purpose of the topic.
func (m *UMPTopicManager) GetDocumentation() string {
	return "UMP (User Management Protocol) Topic Manager: admits 12-field PushDrop tokens that publish " +
		"encrypted CWI-style wallet account descriptors. Used by BRC-100 wallets (SendBSV-Wallet, " +
		"Babbage MetaNet) for cross-device passkey recovery. Anvil indexes the lookup keys " +
		"(presentationHash, recoveryHash) but never decrypts the encrypted recovery primaries — " +
		"that is strictly a client-side wallet responsibility."
}

// GetMetadata returns machine-readable metadata.
func (m *UMPTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"brc":      100,
		"protocol": "UMP",
		"purpose":  "cwi-style-wallet-account-descriptor",
	}
}

// ParseUMPOutput PushDrop-decodes a locking script and validates it as
// a UMP token. Returns (entry, nil) for a valid token, (nil, nil) for a
// non-UMP script, (nil, err) for a malformed-but-PushDrop-shaped output
// that should be logged.
//
// Exported so the lookup service can re-derive UMPEntry from
// admitted output scripts without rebuilding the decode path.
func ParseUMPOutput(scriptBytes []byte) (*UMPEntry, error) {
	if len(scriptBytes) == 0 {
		return nil, nil
	}
	s := script.NewFromBytes(scriptBytes)
	if s == nil {
		return nil, nil
	}
	decoded := pushdrop.Decode(s)
	if decoded == nil {
		return nil, nil
	}
	fields := decoded.Fields
	if len(fields) < UMPMinFields {
		return nil, nil
	}

	entry := &UMPEntry{
		PresentationHash: hex.EncodeToString(fields[6]),
		RecoveryHash:     hex.EncodeToString(fields[7]),
	}

	// v3 detection (matches UMPTopicManager.ts:19-23): a 1-byte field
	// at either index 11 (no profilesEncrypted slot) or index 12 (with
	// profilesEncrypted at 11) signals v3 candidacy.
	hasV3AtIndex11 := len(fields) >= 12 && len(fields[11]) == UMPVersionV3FieldLen
	hasV3AtIndex12 := !hasV3AtIndex11 && len(fields) >= 13 && len(fields[12]) == UMPVersionV3FieldLen
	if !hasV3AtIndex11 && !hasV3AtIndex12 {
		return entry, nil // v1/v2 — admit without v3 validation
	}
	v3Idx := 11
	if hasV3AtIndex12 {
		v3Idx = 12
	}
	if fields[v3Idx][0] != UMPVersionV3 {
		return nil, errors.New("ump: invalid v3 token: umpVersion must be 3")
	}
	kdfAlgIdx := v3Idx + 1
	kdfParamsIdx := v3Idx + 2
	if kdfAlgIdx >= len(fields) || len(fields[kdfAlgIdx]) == 0 {
		return nil, errors.New("ump: invalid v3 token: missing kdfAlgorithm")
	}
	kdfAlg := string(fields[kdfAlgIdx])
	if kdfAlg != UMPKDFArgon2id && kdfAlg != UMPKDFPBKDF2SHA512 {
		return nil, fmt.Errorf("ump: invalid v3 token: unsupported kdfAlgorithm %q", kdfAlg)
	}
	if kdfParamsIdx >= len(fields) || len(fields[kdfParamsIdx]) == 0 {
		return nil, errors.New("ump: invalid v3 token: missing kdfParams")
	}
	var kdfParams struct {
		Iterations uint32 `json:"iterations"`
	}
	if err := json.Unmarshal(fields[kdfParamsIdx], &kdfParams); err != nil {
		return nil, fmt.Errorf("ump: invalid v3 token: malformed kdfParams JSON: %w", err)
	}
	if kdfParams.Iterations == 0 {
		return nil, errors.New("ump: invalid v3 token: kdfParams.iterations must be positive")
	}

	entry.UMPVersion = UMPVersionV3
	entry.KDFAlgorithm = kdfAlg
	entry.KDFIterations = kdfParams.Iterations
	return entry, nil
}
