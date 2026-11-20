package content

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

const testWoCTxid = "3f655413e56f0a353da881ea08de93bb735f279228f201d6804d4d17767cba44"

// realTxid returns the double-SHA256, byte-reversed hash of raw — the same
// value verifyTxidMatch computes — so tests can build a body and the txid
// that genuinely matches it, instead of an arbitrary placeholder.
func realTxid(raw []byte) string {
	return chainhash.DoubleHashH(raw).String()
}

// newWoCStub serves hexBody (or 404 when hexBody is nil) on /tx/{txid}/hex and
// jsonBody (or 404 when it is nil) on the /tx/{txid} JSON fallback, and
// returns a Server pointed at it.
func newWoCStub(t *testing.T, hexBody, jsonBody []byte) *Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tx/{txid}/hex", func(w http.ResponseWriter, r *http.Request) {
		if hexBody == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(hexBody)
	})
	mux.HandleFunc("GET /tx/{txid}", func(w http.ResponseWriter, r *http.Request) {
		if jsonBody == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return NewServer(srv.URL, nil, nil, nil)
}

// assertTooLarge fails unless err is the WoC size-cap error.
func assertTooLarge(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected the WoC size cap to reject the reply, got nil")
	}
	if !errors.Is(err, errWoCResponseTooLarge) || !strings.Contains(err.Error(), "WoC response exceeds size cap") {
		t.Fatalf("expected %q, got: %v", errWoCResponseTooLarge, err)
	}
}

// TestFetchRawTxFromWoC_HexPathCapped: a /hex reply one byte over
// maxWoCTxHexBytes must be refused instead of read into memory whole.
func TestFetchRawTxFromWoC_HexPathCapped(t *testing.T) {
	s := newWoCStub(t, bytes.Repeat([]byte("a"), maxWoCTxHexBytes+1), nil)
	_, err := s.fetchRawTxFromWoC(testWoCTxid)
	assertTooLarge(t, err)
}

// TestFetchRawTxFromWoC_JSONFallbackCapped: when /hex fails, the JSON
// fallback is held to the same cap.
func TestFetchRawTxFromWoC_JSONFallbackCapped(t *testing.T) {
	var body bytes.Buffer
	body.WriteString(`{"hex":"`)
	body.Write(bytes.Repeat([]byte("a"), maxWoCTxHexBytes))
	body.WriteString(`"}`)
	s := newWoCStub(t, nil, body.Bytes())
	_, err := s.fetchRawTxFromWoC(testWoCTxid)
	assertTooLarge(t, err)
}

// TestFetchRawTxFromWoC_AtCapAccepted: a reply of exactly maxWoCTxHexBytes is
// still served, so the cap only refuses what is over it. The body must also
// be the real preimage of the requested txid, now that fetchRawTxFromWoC
// verifies every reply.
func TestFetchRawTxFromWoC_AtCapAccepted(t *testing.T) {
	raw := bytes.Repeat([]byte{0xaa}, maxWoCTxHexBytes/2)
	hexBody := []byte(hex.EncodeToString(raw))
	if len(hexBody) != maxWoCTxHexBytes {
		t.Fatalf("test setup: hex body is %d bytes, want %d", len(hexBody), maxWoCTxHexBytes)
	}
	txid := realTxid(raw)

	s := newWoCStub(t, hexBody, nil)
	got, err := s.fetchRawTxFromWoC(txid)
	if err != nil {
		t.Fatalf("a reply at the cap, matching the requested txid, must be accepted, got: %v", err)
	}
	if len(got) != maxWoCTxHexBytes {
		t.Fatalf("expected %d hex chars, got %d", maxWoCTxHexBytes, len(got))
	}
}

// TestFetchRawTxFromWoC_SmallRepliesUnchanged: ordinary replies on both paths
// decode as before the cap (the /hex body is trimmed, the JSON hex
// returned), given each body's real matching txid.
func TestFetchRawTxFromWoC_SmallRepliesUnchanged(t *testing.T) {
	hexRaw := []byte{0x01, 0x00, 0xbe, 0xef}
	got, err := newWoCStub(t, []byte(" 0100beef\n"), nil).fetchRawTxFromWoC(realTxid(hexRaw))
	if err != nil || got != "0100beef" {
		t.Fatalf("hex path: got %q, %v; want \"0100beef\"", got, err)
	}

	jsonRaw := []byte{0x02, 0x00, 0xbe, 0xef}
	got, err = newWoCStub(t, nil, []byte(`{"txid":"x","hex":"0200beef"}`)).fetchRawTxFromWoC(realTxid(jsonRaw))
	if err != nil || got != "0200beef" {
		t.Fatalf("JSON fallback: got %q, %v; want \"0200beef\"", got, err)
	}
}

// TestFetchRawTxFromWoC_HexMismatchRejected: a fake WhatsOnChain that
// returns a different tx's bytes — on both the hex endpoint and its JSON
// fallback — must never have those bytes served, and the final error must
// say so. (TestFetchRawTxFromWoC_JSONFallbackOnHexMismatch below covers the
// case where the JSON endpoint redeems a bad hex reply with correct bytes.)
func TestFetchRawTxFromWoC_HexMismatchRejected(t *testing.T) {
	wrongRaw := []byte{0xde, 0xad, 0xbe, 0xef}
	requestedTxid := realTxid([]byte{0x00, 0x01, 0x02, 0x03}) // a different, real txid

	s := newWoCStub(t, []byte(hex.EncodeToString(wrongRaw)), []byte(`{"hex":"deadbeef"}`))
	got, err := s.fetchRawTxFromWoC(requestedTxid)
	if got != "" {
		t.Fatalf("mismatched bytes must never be returned, got %q", got)
	}
	if !errors.Is(err, errTxidMismatch) {
		t.Fatalf("expected errTxidMismatch, got: %v", err)
	}
}

// TestFetchRawTxFromWoC_JSONFallbackOnHexMismatch: when the hex endpoint's
// bytes don't match the requested txid, fetchRawTxFromWoC must fall through
// to the JSON endpoint — a mismatch is "that source failed", not a final
// answer — and return the JSON endpoint's (correct) bytes.
func TestFetchRawTxFromWoC_JSONFallbackOnHexMismatch(t *testing.T) {
	wrongRaw := []byte{0xde, 0xad, 0xbe, 0xef}
	correctRaw := []byte{0x02, 0x00, 0xbe, 0xef}
	txid := realTxid(correctRaw)

	s := newWoCStub(t, []byte(hex.EncodeToString(wrongRaw)), []byte(`{"hex":"0200beef"}`))
	got, err := s.fetchRawTxFromWoC(txid)
	if err != nil {
		t.Fatalf("expected the JSON fallback to succeed after the hex mismatch, got: %v", err)
	}
	if got != "0200beef" {
		t.Fatalf("expected the JSON fallback's bytes, got %q", got)
	}
}

// TestDecodeWoCMetadata_OversizeRejected: a body one byte over
// maxWoCMetadataBytes must be refused by the same size-cap error as the hex
// path's cap, just at the smaller metadata budget.
func TestDecodeWoCMetadata_OversizeRejected(t *testing.T) {
	body := bytes.NewReader(bytes.Repeat([]byte("a"), maxWoCMetadataBytes+1))
	var v map[string]interface{}
	err := decodeWoCMetadata(body, &v)
	assertTooLarge(t, err)
}

// TestDecodeWoCMetadata_AtCapAccepted: exactly maxWoCMetadataBytes of valid
// JSON still decodes, so the cap only refuses what is over it.
func TestDecodeWoCMetadata_AtCapAccepted(t *testing.T) {
	padding := maxWoCMetadataBytes - len(`{"block_hash":"x","pad":""}`)
	body := []byte(`{"block_hash":"x","pad":"` + strings.Repeat("a", padding) + `"}`)
	if len(body) != maxWoCMetadataBytes {
		t.Fatalf("test setup: body is %d bytes, want %d", len(body), maxWoCMetadataBytes)
	}
	var v struct {
		BlockHash string `json:"block_hash"`
	}
	if err := decodeWoCMetadata(bytes.NewReader(body), &v); err != nil {
		t.Fatalf("a body at the cap must decode, got: %v", err)
	}
	if v.BlockHash != "x" {
		t.Fatalf("expected block_hash=x, got %q", v.BlockHash)
	}
}

// TestTryWoCStatus_OversizeReplyIgnored is the call-site-level counterpart:
// findBlockHash's WoC status probe (serve.go's original :249, now
// fetch.go's tryWoCStatus) must come back empty — not panic, not decode
// garbage — when the status endpoint's reply exceeds the metadata cap.
func TestTryWoCStatus_OversizeReplyIgnored(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tx/{txid}/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"block_hash":"` + strings.Repeat("a", maxWoCMetadataBytes) + `"}`))
	})
	stub := httptest.NewServer(mux)
	t.Cleanup(stub.Close)

	s := NewServer(stub.URL, nil, nil, nil)
	if got := s.tryWoCStatus(testWoCTxid); got != "" {
		t.Fatalf("expected an oversize status reply to be ignored, got %q", got)
	}
}
