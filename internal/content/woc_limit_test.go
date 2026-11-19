package content

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testWoCTxid = "3f655413e56f0a353da881ea08de93bb735f279228f201d6804d4d17767cba44"

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
// still served, so the cap only refuses what is over it.
func TestFetchRawTxFromWoC_AtCapAccepted(t *testing.T) {
	s := newWoCStub(t, bytes.Repeat([]byte("a"), maxWoCTxHexBytes), nil)
	got, err := s.fetchRawTxFromWoC(testWoCTxid)
	if err != nil {
		t.Fatalf("a reply at the cap must be accepted, got: %v", err)
	}
	if len(got) != maxWoCTxHexBytes {
		t.Fatalf("expected %d hex chars, got %d", maxWoCTxHexBytes, len(got))
	}
}

// TestFetchRawTxFromWoC_SmallRepliesUnchanged: ordinary replies on both paths
// decode as before the cap (the /hex body is trimmed, the JSON hex returned).
func TestFetchRawTxFromWoC_SmallRepliesUnchanged(t *testing.T) {
	got, err := newWoCStub(t, []byte(" 0100beef\n"), nil).fetchRawTxFromWoC(testWoCTxid)
	if err != nil || got != "0100beef" {
		t.Fatalf("hex path: got %q, %v; want \"0100beef\"", got, err)
	}
	got, err = newWoCStub(t, nil, []byte(`{"txid":"x","hex":"0200beef"}`)).fetchRawTxFromWoC(testWoCTxid)
	if err != nil || got != "0200beef" {
		t.Fatalf("JSON fallback: got %q, %v; want \"0200beef\"", got, err)
	}
}
