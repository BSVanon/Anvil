// Package topics contains overlay topic managers for the Anvil overlay engine.
//
// Each topic manager implements overlay.TopicManager and decides which
// transaction outputs are relevant to its topic.
package topics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// UHRPTopicName is the BRC-87 standard name for the UHRP topic.
const UHRPTopicName = "tm_uhrp"

// UHRPProtocolID is the protocol identifier in BRC-48 push-drop scripts.
const UHRPProtocolID = "UHRP"

// UHRPEntry is the metadata stored for each admitted UHRP output, legacy
// OP_RETURN or canonical BRC-26 PushDrop alike.
type UHRPEntry struct {
	// ContentHash is the SHA-256 hash of the hosted file.
	ContentHash string `json:"content_hash"`
	// URL is where the content can be fetched.
	URL string `json:"url,omitempty"`
	// ContentType is the MIME type of the hosted file. Legacy-only;
	// canonical BRC-26 adverts carry no content-type field.
	ContentType string `json:"content_type,omitempty"`
	// BRC26 marks this entry as a canonical BRC-26 PushDrop advertisement
	// rather than a legacy OP_FALSE OP_RETURN advertisement. The zero
	// value (false) is correct for every legacy entry, including ones
	// stored before this field existed.
	BRC26 bool `json:"brc26,omitempty"`
	// IdentityKey is the hex-encoded 33-byte compressed host public key
	// (BRC-26 field[0]). Empty for legacy entries.
	IdentityKey string `json:"identity_key,omitempty"`
	// Expiry is the BRC-26 advertisement's expiry as an absolute
	// Unix-seconds timestamp (field[3]). Confirmed against the canonical
	// resolver, which skips an advert once `expiryTime < currentTime`
	// (ts-sdk storage/StorageDownloader.ts) — not a relative duration.
	// Zero for legacy entries, which have no expiry concept.
	Expiry int64 `json:"expiry,omitempty"`
}

// UHRPTopicManager implements overlay.TopicManager for BRC-26 UHRP.
//
// It admits two shapes of output:
//
//   - Canonical BRC-26: a PushDrop output carrying [identityKey(33B),
//     sha256(32B), https URL, varint expirySeconds, varint size] plus a
//     trailing signature, validated by decodeUHRPBRC26 + verifyBRC26Linkage
//     (uhrp_brc26.go — ported from UHRPTopicManager.ts +
//     isTokenSignatureCorrectlyLinked.ts). Being a real PushDrop output,
//     this format is spendable: revoking an advertisement is an ordinary
//     spend of its UTXO.
//   - Legacy: OP_FALSE OP_RETURN "UHRP" <sha256_hash_hex> [<url>]
//     [<content_type>], read-only. OP_RETURN outputs are unspendable, so
//     a legacy advertisement can never be revoked — admitted as-is so
//     existing entries keep resolving.
//
// When an admitted output (of either shape) is later spent, the overlay
// engine's own spend-tracking removes it from storage and notifies every
// lookup service unconditionally — independent of this topic's
// CoinsToRetain/CoinsRemoved choice below, which only affects GASP
// provenance linking for an output newly admitted in the SAME transaction.
type UHRPTopicManager struct {
	log          admitLogger
	anyoneWallet *wallet.ProtoWallet
}

// NewUHRPTopicManager creates a UHRP topic manager. It holds a single
// canonical "anyone" ProtoWallet for BRC-26 signature-linkage verification
// (see verifyBRC26Linkage); construction of the anyone wallet is
// deterministic and never fails in practice, but a nil wallet is guarded
// at verify time. Pass WithLogger to surface per-output admission-skip
// reasons; with no options the manager stays silent.
func NewUHRPTopicManager(opts ...TopicOption) *UHRPTopicManager {
	log := newAdmitLogger(opts...)
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypeAnyone})
	if err != nil {
		// The anyone constructor only builds a key deriver from a nil
		// root key; it cannot error. Guard defensively anyway so a
		// future SDK change surfaces as a clean admission-skip rather
		// than a panic (mirrors kvstore.go's identical guard).
		return &UHRPTopicManager{log: log, anyoneWallet: nil}
	}
	return &UHRPTopicManager{log: log, anyoneWallet: w}
}

// Admit evaluates a transaction for UHRP content advertisements, canonical
// BRC-26 PushDrop first, falling back to the legacy OP_RETURN format for
// any output that isn't PushDrop-shaped.
func (u *UHRPTopicManager) Admit(txData []byte, previousUTXOs []overlay.AdmittedOutput) (*overlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}
	ctx := context.Background()

	var outputsToAdmit []int
	outputMetadata := make(map[int]json.RawMessage)

	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		scriptBytes := out.LockingScript.Bytes()

		brc26, decErr := decodeUHRPBRC26(scriptBytes)
		if decErr != nil {
			// PushDrop-shaped but fails a canonical BRC-26 shape check
			// (field count / hash length / HTTPS / expiry / size).
			u.log.skip(UHRPTopicName, i, decErr)
			continue
		}
		if brc26 != nil {
			ok, linkErr := u.verifyBRC26Linkage(ctx, brc26)
			if linkErr != nil {
				u.log.skip(UHRPTopicName, i, linkErr)
				continue
			}
			if !ok {
				u.log.skip(UHRPTopicName, i, "signature is not properly linked to identityKey")
				continue
			}
			outputsToAdmit = append(outputsToAdmit, i)
			if meta, merr := json.Marshal(brc26.toEntry()); merr == nil {
				outputMetadata[i] = meta
			}
			continue
		}

		// Not PushDrop-shaped at all — try the legacy format.
		entry, reason := classifyUHRPOutput(scriptBytes)
		if entry == nil {
			if reason != "" {
				// UHRP-tagged OP_RETURN whose hash field is malformed —
				// log the skip reason so a bad advertisement is
				// diagnosable. Non-UHRP outputs (reason == "") are silent.
				u.log.skip(UHRPTopicName, i, reason)
			}
			continue
		}
		outputsToAdmit = append(outputsToAdmit, i)
		if meta, merr := json.Marshal(entry); merr == nil {
			outputMetadata[i] = meta
		}
	}

	// Canonical UHRPTopicManager.ts returns `coinsToRetain: previousCoins`
	// for every coin this tx spends that this topic had previously
	// admitted — not coinsRemoved. Matched here. (Corrected divergence:
	// this topic previously set CoinsRemoved instead, which was moot while
	// only the unspendable legacy format existed, since previousUTXOs was
	// then always empty — see the package doc comment for why this field
	// doesn't govern whether a spent advert keeps resolving.)
	var coinsToRetain []int
	for i := range previousUTXOs {
		coinsToRetain = append(coinsToRetain, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsToRetain) == 0 {
		u.log.nothingAdmitted(UHRPTopicName)
		return nil, nil // nothing relevant
	}

	return &overlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  coinsToRetain,
		CoinsRemoved:   nil,
		OutputMetadata: outputMetadata,
	}, nil
}

// GetDocumentation returns a description of the UHRP topic.
func (u *UHRPTopicManager) GetDocumentation() string {
	return "UHRP (BRC-26): Universal Hash Resolution Protocol. Tracks content availability advertisements — maps SHA-256 file hashes to hosting locations."
}

// GetMetadata returns machine-readable metadata about UHRP.
func (u *UHRPTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"brc":      26,
		"protocol": UHRPProtocolID,
		"purpose":  "content-availability-advertisement",
	}
}

// ParseUHRPOutput checks if a script is a UHRP advertisement, canonical
// BRC-26 PushDrop first, falling back to the legacy
// OP_FALSE OP_RETURN <"UHRP"> <sha256_hash> [<url>] [<content_type>]
// format. Returns nil for any script that is neither. This re-derives
// metadata from an output the caller already knows was admitted — it does
// NOT verify a BRC-26 output's signature (Admit does that once, at
// admission time); the single-value return keeps this a drop-in for its
// existing callers (the lookup service, legacyshim's metadata parser).
// Callers that want the malformed-vs-not-mine distinction, or BRC-26
// validation detail, for skip logging use classifyUHRPOutput /
// decodeUHRPBRC26 directly (Admit does).
func ParseUHRPOutput(script []byte) *UHRPEntry {
	if d, err := decodeUHRPBRC26(script); err == nil && d != nil {
		return d.toEntry()
	}
	entry, _ := classifyUHRPOutput(script)
	return entry
}

// classifyUHRPOutput decodes a locking script as a UHRP advertisement.
// It returns (entry, "") for a valid advertisement and (nil, "") for a
// script that is simply not a UHRP output (not OP_RETURN, wrong protocol
// tag, too few fields). It returns (nil, reason) only when the output IS
// UHRP-tagged but malformed (currently: an invalid content-hash length),
// so admission can log why an otherwise-UHRP advertisement bounced
// instead of dropping it silently.
func classifyUHRPOutput(script []byte) (*UHRPEntry, string) {
	if len(script) < 6 {
		return nil, ""
	}

	// OP_FALSE (0x00) OP_RETURN (0x6a)
	if script[0] != 0x00 || script[1] != 0x6a {
		return nil, ""
	}

	// Parse push data fields after OP_FALSE OP_RETURN
	fields := parsePushDataFields(script[2:])
	if len(fields) < 2 {
		return nil, ""
	}

	// Field 0: protocol ID must be "UHRP"
	if string(fields[0]) != UHRPProtocolID {
		return nil, ""
	}

	// Field 1: SHA-256 hash (32 bytes raw or 64 chars hex)
	hashField := fields[1]
	var contentHash string
	switch len(hashField) {
	case 32:
		contentHash = hex.EncodeToString(hashField)
	case 64:
		// Already hex-encoded
		contentHash = string(hashField)
	default:
		return nil, fmt.Sprintf("invalid UHRP content-hash length %d (want 32 raw bytes or 64 hex chars)", len(hashField))
	}

	entry := &UHRPEntry{
		ContentHash: contentHash,
	}

	// Optional field 2: URL
	if len(fields) > 2 {
		entry.URL = string(fields[2])
	}

	// Optional field 3: content type
	if len(fields) > 3 {
		entry.ContentType = string(fields[3])
	}

	return entry, ""
}

// parsePushDataFields extracts push data elements from a script fragment.
// Handles OP_PUSHDATA1, OP_PUSHDATA2, and direct push (1-75 bytes).
func parsePushDataFields(script []byte) [][]byte {
	var fields [][]byte
	pos := 0

	for pos < len(script) {
		op := script[pos]
		pos++

		switch {
		case op == 0x00:
			// OP_0 — empty push
			fields = append(fields, []byte{})
		case op >= 0x01 && op <= 0x4b:
			// Direct push: next op bytes
			size := int(op)
			if pos+size > len(script) {
				return fields
			}
			fields = append(fields, script[pos:pos+size])
			pos += size
		case op == 0x4c:
			// OP_PUSHDATA1: next byte is length
			if pos >= len(script) {
				return fields
			}
			size := int(script[pos])
			pos++
			if pos+size > len(script) {
				return fields
			}
			fields = append(fields, script[pos:pos+size])
			pos += size
		case op == 0x4d:
			// OP_PUSHDATA2: next 2 bytes are length (little-endian)
			if pos+2 > len(script) {
				return fields
			}
			size := int(script[pos]) | int(script[pos+1])<<8
			pos += 2
			if pos+size > len(script) {
				return fields
			}
			fields = append(fields, script[pos:pos+size])
			pos += size
		default:
			// Any opcode that's not a push terminates field parsing
			return fields
		}
	}

	return fields
}

// HashContent computes the SHA-256 hash of content for UHRP advertisements.
func HashContent(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// BuildUHRPScript builds a UHRP advertisement locking script.
// OP_FALSE OP_RETURN "UHRP" <hash> [<url>] [<content_type>]
func BuildUHRPScript(contentHash string, url string, contentType string) ([]byte, error) {
	hashBytes, err := hex.DecodeString(contentHash)
	if err != nil || len(hashBytes) != 32 {
		return nil, fmt.Errorf("content hash must be 64-char hex (32 bytes)")
	}

	var script []byte
	script = append(script, 0x00, 0x6a) // OP_FALSE OP_RETURN

	// Push "UHRP"
	protocol := []byte(UHRPProtocolID)
	script = append(script, byte(len(protocol))) // #nosec G115 // "UHRP" is always 4 bytes
	script = append(script, protocol...)

	// Push hash (32 bytes)
	script = append(script, byte(len(hashBytes))) // #nosec G115 // SHA-256 hash is always 32 bytes
	script = append(script, hashBytes...)

	// Optional: push URL (truncate to 255 bytes if needed — single-byte pushdata limit)
	if url != "" {
		urlBytes := []byte(url)
		if len(urlBytes) > 255 {
			urlBytes = urlBytes[:255]
		}
		script = appendPushData(script, urlBytes)
		script = append(script, urlBytes...)
	}

	// Optional: push content type (truncate to 255 bytes if needed)
	if contentType != "" {
		ctBytes := []byte(contentType)
		if len(ctBytes) > 255 {
			ctBytes = ctBytes[:255]
		}
		script = appendPushData(script, ctBytes)
		script = append(script, ctBytes...)
	}

	return script, nil
}

// Ensure UHRPTopicManager implements TopicManager at compile time.
var _ overlay.TopicManager = (*UHRPTopicManager)(nil)

// appendPushData appends the correct Bitcoin script push opcode for a data slice.
// Caller must ensure len(data) <= 255 before calling.
// <=75 bytes: direct push. 76-255: OP_PUSHDATA1.
func appendPushData(script, data []byte) []byte {
	l := len(data)
	if l <= 75 {
		return append(script, byte(l)) // #nosec G115 // bounded by <= 75
	}
	return append(script, 0x4c, byte(l)) // #nosec G115 // caller ensures <= 255
}
