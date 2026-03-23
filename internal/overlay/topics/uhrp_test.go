package topics

import (
	"encoding/hex"
	"testing"
)

func TestBuildAndParseUHRPScript(t *testing.T) {
	contentHash := HashContent([]byte("hello world"))
	url := "https://anvil.sendbsv.com/content/abc123_0"
	contentType := "text/html"

	script, err := BuildUHRPScript(contentHash, url, contentType)
	if err != nil {
		t.Fatalf("BuildUHRPScript: %v", err)
	}

	// Parse it back
	entry := parseUHRPOutput(script)
	if entry == nil {
		t.Fatal("parseUHRPOutput returned nil")
	}
	if entry.ContentHash != contentHash {
		t.Fatalf("hash mismatch: got %s, want %s", entry.ContentHash, contentHash)
	}
	if entry.URL != url {
		t.Fatalf("url mismatch: got %s, want %s", entry.URL, url)
	}
	if entry.ContentType != contentType {
		t.Fatalf("content type mismatch: got %s, want %s", entry.ContentType, contentType)
	}
}

func TestBuildUHRPScriptMinimal(t *testing.T) {
	contentHash := HashContent([]byte("test"))
	script, err := BuildUHRPScript(contentHash, "", "")
	if err != nil {
		t.Fatal(err)
	}

	entry := parseUHRPOutput(script)
	if entry == nil {
		t.Fatal("parseUHRPOutput returned nil for minimal script")
	}
	if entry.ContentHash != contentHash {
		t.Fatalf("hash mismatch: %s vs %s", entry.ContentHash, contentHash)
	}
	if entry.URL != "" {
		t.Fatalf("expected empty URL, got %s", entry.URL)
	}
}

func TestParseUHRPOutputRejectsNonUHRP(t *testing.T) {
	// OP_FALSE OP_RETURN "SHIP" <data>
	script := []byte{0x00, 0x6a, 0x04}
	script = append(script, []byte("SHIP")...)
	script = append(script, 0x20) // 32 bytes
	script = append(script, make([]byte, 32)...)

	entry := parseUHRPOutput(script)
	if entry != nil {
		t.Fatal("should reject non-UHRP protocol")
	}
}

func TestParseUHRPOutputRejectsShortHash(t *testing.T) {
	// OP_FALSE OP_RETURN "UHRP" <16 bytes — too short>
	script := []byte{0x00, 0x6a, 0x04}
	script = append(script, []byte("UHRP")...)
	script = append(script, 0x10) // 16 bytes
	script = append(script, make([]byte, 16)...)

	entry := parseUHRPOutput(script)
	if entry != nil {
		t.Fatal("should reject short hash")
	}
}

func TestHashContent(t *testing.T) {
	hash := HashContent([]byte("hello world"))
	// Known SHA-256 of "hello world"
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Fatalf("hash mismatch: got %s, want %s", hash, expected)
	}
}

func TestParsePushDataFields(t *testing.T) {
	// Build: 0x04 "UHRP" 0x20 <32 zero bytes>
	var script []byte
	script = append(script, 0x04) // push 4 bytes
	script = append(script, []byte("UHRP")...)
	script = append(script, 0x20) // push 32 bytes
	script = append(script, make([]byte, 32)...)

	fields := parsePushDataFields(script)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}
	if string(fields[0]) != "UHRP" {
		t.Fatalf("field 0: got %s, want UHRP", string(fields[0]))
	}
	if hex.EncodeToString(fields[1]) != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("field 1: unexpected hash")
	}
}
