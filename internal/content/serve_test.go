package content

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeRealInscription(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	s := NewServer("", nil, nil, nil)

	// Use one of the Explorer's inscribed files (favicon)
	// 3f655413e56f0a353da881ea08de93bb735f279228f201d6804d4d17767cba44_0
	req := httptest.NewRequest("GET", "/content/3f655413e56f0a353da881ea08de93bb735f279228f201d6804d4d17767cba44_0", nil)
	req.SetPathValue("origin", "3f655413e56f0a353da881ea08de93bb735f279228f201d6804d4d17767cba44_0")
	w := httptest.NewRecorder()

	s.ServeContent(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct == "" {
		t.Fatal("missing Content-Type header")
	}
	t.Logf("Content-Type: %s, Size: %d bytes", ct, w.Body.Len())

	if w.Body.Len() == 0 {
		t.Fatal("empty response body")
	}

	// Verify caching headers
	cc := w.Header().Get("Cache-Control")
	if cc == "" {
		t.Fatal("missing Cache-Control header")
	}
	cors := w.Header().Get("Access-Control-Allow-Origin")
	if cors != "*" {
		t.Fatalf("expected CORS *, got %s", cors)
	}
}

func TestServeInvalidTxid(t *testing.T) {
	s := NewServer("", nil, nil, nil)

	req := httptest.NewRequest("GET", "/content/invalidtxid_0", nil)
	req.SetPathValue("origin", "invalidtxid_0")
	w := httptest.NewRecorder()

	s.ServeContent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid txid, got %d", w.Code)
	}
}

func TestServeMissingOrigin(t *testing.T) {
	s := NewServer("", nil, nil, nil)

	req := httptest.NewRequest("GET", "/content/", nil)
	req.SetPathValue("origin", "")
	w := httptest.NewRecorder()

	s.ServeContent(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing origin, got %d", w.Code)
	}
}

// TestExtractOutputScript_MultiOutput builds a minimal raw transaction with 3 outputs
// and verifies that extractOutputScript returns the correct script for each vout.
func TestExtractOutputScript_MultiOutput(t *testing.T) {
	// Manually construct a minimal valid transaction:
	// Version: 01000000
	// 0 inputs (for simplicity — not a valid real tx, but sufficient for output parsing)
	// 3 outputs with distinct scripts
	tx := buildTestTx([][]byte{
		{0x6a, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f},       // output 0: OP_RETURN "hello"
		{0x6a, 0x05, 0x77, 0x6f, 0x72, 0x6c, 0x64},       // output 1: OP_RETURN "world"
		{0x6a, 0x03, 0x66, 0x6f, 0x6f},                     // output 2: OP_RETURN "foo"
	})

	// Verify each output returns the correct script
	for i, expected := range []string{"hello", "world", "foo"} {
		script, err := extractOutputScript(tx, i)
		if err != nil {
			t.Fatalf("vout %d: %v", i, err)
		}
		// Script starts with OP_RETURN (0x6a) + push length + data
		if len(script) < 3 {
			t.Fatalf("vout %d: script too short: %d bytes", i, len(script))
		}
		// Extract the pushed data (skip OP_RETURN + length byte)
		data := string(script[2:])
		if data != expected {
			t.Fatalf("vout %d: expected %q, got %q", i, expected, data)
		}
	}

	// Out-of-range vout should error
	_, err := extractOutputScript(tx, 3)
	if err == nil {
		t.Fatal("expected error for vout 3 on 3-output tx")
	}
}

// TestParseInscription_SpecificVout verifies that parseInscription picks the correct
// output in a multi-output transaction, not just the first match.
func TestParseInscription_SpecificVout(t *testing.T) {
	// Build a tx where output 0 has no inscription and output 1 has a B:// inscription
	bAddr := "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
	// B:// script: OP_RETURN <B-addr> <data> <content-type>
	bScript := buildBProtocolScript(bAddr, []byte("test-data-here"), "text/plain")
	plainScript := []byte{0x76, 0xa9, 0x14} // partial P2PKH (no inscription)

	tx := buildTestTx([][]byte{plainScript, bScript})
	txHex := hex.EncodeToString(tx)

	// vout 0 should NOT have an inscription
	_, err := parseInscription(txHex, "0")
	if err == nil {
		t.Fatal("expected no inscription in vout 0")
	}

	// vout 1 SHOULD have the B:// inscription
	insc, err := parseInscription(txHex, "1")
	if err != nil {
		t.Fatalf("vout 1 should have inscription: %v", err)
	}
	if insc.ContentType != "text/plain" {
		t.Fatalf("expected text/plain, got %s", insc.ContentType)
	}
	if string(insc.Data) != "test-data-here" {
		t.Fatalf("expected 'test-data-here', got %q", string(insc.Data))
	}
}

// ── Test helpers ──

// buildTestTx constructs a minimal raw transaction with 0 inputs and N outputs.
func buildTestTx(scripts [][]byte) []byte {
	var buf []byte
	// Version (4 bytes LE)
	buf = append(buf, 0x01, 0x00, 0x00, 0x00)
	// Input count: 0
	buf = append(buf, 0x00)
	// Output count
	buf = append(buf, byte(len(scripts)))
	for _, script := range scripts {
		// Value: 1 sat (8 bytes LE)
		buf = append(buf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		// Script length (varint)
		buf = append(buf, byte(len(script)))
		// Script
		buf = append(buf, script...)
	}
	// Locktime (4 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	return buf
}

// buildBProtocolScript constructs a B:// OP_RETURN script.
func buildBProtocolScript(bAddr string, data []byte, contentType string) []byte {
	var buf []byte
	buf = append(buf, 0x6a) // OP_RETURN
	// Push B address
	addrBytes := []byte(bAddr)
	buf = append(buf, byte(len(addrBytes)))
	buf = append(buf, addrBytes...)
	// Push data
	if len(data) < 0x4c {
		buf = append(buf, byte(len(data)))
	} else {
		buf = append(buf, 0x4c, byte(len(data))) // OP_PUSHDATA1
	}
	buf = append(buf, data...)
	// Push content-type
	ctBytes := []byte(contentType)
	buf = append(buf, byte(len(ctBytes)))
	buf = append(buf, ctBytes...)
	return buf
}
