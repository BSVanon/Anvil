package topics

// Legacy UHRP advertisement format: OP_FALSE OP_RETURN "UHRP"
// <sha256_hash> [<url>] [<content_type>]. Predates the canonical BRC-26
// PushDrop format this package also admits (uhrp_brc26.go) — kept so
// entries minted before BRC-26 support keep resolving. OP_RETURN outputs
// are unspendable, so a legacy advertisement can never be revoked (see
// uhrp.go's package doc comment).
//
// Split out of uhrp.go, which was growing past this package's established
// per-file size after the BRC-26 implementation was added; this
// file and uhrp.go together replace what was one file, with no behaviour
// change (mirrors the equivalent split already done on the lookups side,
// uhrp.go / uhrp_filter.go).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

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
