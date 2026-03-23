// Package topics contains overlay topic managers for the Anvil overlay engine.
//
// Each topic manager implements overlay.TopicManager and decides which
// transaction outputs are relevant to its topic.
package topics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// UHRPTopicName is the BRC-87 standard name for the UHRP topic.
const UHRPTopicName = "tm_uhrp"

// UHRPProtocolID is the protocol identifier in BRC-48 push-drop scripts.
const UHRPProtocolID = "UHRP"

// UHRPEntry is the metadata stored for each admitted UHRP output.
type UHRPEntry struct {
	// ContentHash is the SHA-256 hash of the hosted file.
	ContentHash string `json:"content_hash"`
	// URL is where the content can be fetched.
	URL string `json:"url,omitempty"`
	// ContentType is the MIME type of the hosted file.
	ContentType string `json:"content_type,omitempty"`
}

// UHRPTopicManager implements overlay.TopicManager for BRC-26 UHRP.
//
// It admits outputs that advertise content availability:
// OP_FALSE OP_RETURN "UHRP" <sha256_hash_hex> [<url>] [<content_type>]
//
// When a UHRP UTXO is spent, the advertisement is removed (content no longer
// advertised at that location). This enables versioning: spend old token,
// create new one with updated hash.
type UHRPTopicManager struct{}

// NewUHRPTopicManager creates a UHRP topic manager.
func NewUHRPTopicManager() *UHRPTopicManager {
	return &UHRPTopicManager{}
}

// Admit evaluates a transaction for UHRP content advertisements.
func (u *UHRPTopicManager) Admit(txData []byte, previousUTXOs []overlay.AdmittedOutput) (*overlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}

	var outputsToAdmit []int
	var coinsRemoved []int
	outputMetadata := make(map[int]json.RawMessage)

	// Check each output for UHRP advertisement pattern
	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}

		entry := parseUHRPOutput(out.LockingScript.Bytes())
		if entry != nil {
			outputsToAdmit = append(outputsToAdmit, i)
			// Serialize UHRP entry as metadata for storage
			meta, err := json.Marshal(entry)
			if err == nil {
				outputMetadata[i] = meta
			}
		}
	}

	// Mark all previously-admitted UTXOs as spent (removed)
	for i := range previousUTXOs {
		coinsRemoved = append(coinsRemoved, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsRemoved) == 0 {
		return nil, nil // nothing relevant
	}

	return &overlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  nil,
		CoinsRemoved:   coinsRemoved,
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

// parseUHRPOutput checks if a script is a UHRP advertisement.
// Expected format: OP_FALSE OP_RETURN <"UHRP"> <sha256_hash> [<url>] [<content_type>]
func parseUHRPOutput(script []byte) *UHRPEntry {
	if len(script) < 6 {
		return nil
	}

	// OP_FALSE (0x00) OP_RETURN (0x6a)
	if script[0] != 0x00 || script[1] != 0x6a {
		return nil
	}

	// Parse push data fields after OP_FALSE OP_RETURN
	fields := parsePushDataFields(script[2:])
	if len(fields) < 2 {
		return nil
	}

	// Field 0: protocol ID must be "UHRP"
	if string(fields[0]) != UHRPProtocolID {
		return nil
	}

	// Field 1: SHA-256 hash (32 bytes raw or 64 chars hex)
	hashField := fields[1]
	var contentHash string
	if len(hashField) == 32 {
		contentHash = hex.EncodeToString(hashField)
	} else if len(hashField) == 64 {
		// Already hex-encoded
		contentHash = string(hashField)
	} else {
		return nil // invalid hash length
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

	return entry
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
	script = append(script, byte(len(protocol)))
	script = append(script, protocol...)

	// Push hash (32 bytes)
	script = append(script, byte(len(hashBytes)))
	script = append(script, hashBytes...)

	// Optional: push URL
	if url != "" {
		urlBytes := []byte(url)
		if len(urlBytes) <= 75 {
			script = append(script, byte(len(urlBytes)))
		} else {
			script = append(script, 0x4c, byte(len(urlBytes))) // OP_PUSHDATA1
		}
		script = append(script, urlBytes...)
	}

	// Optional: push content type
	if contentType != "" {
		ctBytes := []byte(contentType)
		script = append(script, byte(len(ctBytes)))
		script = append(script, ctBytes...)
	}

	return script, nil
}

// Ensure UHRPTopicManager implements TopicManager at compile time.
var _ overlay.TopicManager = (*UHRPTopicManager)(nil)

// suppress unused import
var _ = json.Marshal
