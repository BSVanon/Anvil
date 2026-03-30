package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/mempool"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

func testServerWithWatcher(t *testing.T) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-watch-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-watch-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-watch-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	watcher := mempool.NewWatcher(nil, slog.Default())

	return NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es,
		Validator:   spv.NewValidator(hs),
		Broadcaster: txrelay.NewBroadcaster(txrelay.NewMempool(), nil, slog.Default()),
		AuthToken:   "test-token",
		Logger:      slog.Default(),
		Watcher:     watcher,
	})
}

func TestWatchAddRequiresAuth(t *testing.T) {
	srv := testServerWithWatcher(t)
	body := `{"addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}`
	req := httptest.NewRequest("POST", "/mempool/watch", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}
}

func TestWatchAddAndList(t *testing.T) {
	srv := testServerWithWatcher(t)

	// Add an address (authenticated)
	body := `{"addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}`
	req := httptest.NewRequest("POST", "/mempool/watch", strings.NewReader(body))
	req.Header.Set("X-Anvil-Auth", "test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var addResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &addResp)
	if int(addResp["added"].(float64)) != 1 {
		t.Fatalf("expected 1 added, got %v", addResp["added"])
	}
	if int(addResp["watching"].(float64)) != 1 {
		t.Fatalf("expected watching=1, got %v", addResp["watching"])
	}

	// List (no auth required — open read)
	req2 := httptest.NewRequest("GET", "/mempool/watch", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("list expected 200, got %d", w2.Code)
	}

	var listResp map[string]interface{}
	json.Unmarshal(w2.Body.Bytes(), &listResp)
	addrs := listResp["addresses"].([]interface{})
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address in list, got %d", len(addrs))
	}
}

func TestWatchAddInvalidAddress(t *testing.T) {
	srv := testServerWithWatcher(t)

	body := `{"addresses":["not-valid"]}`
	req := httptest.NewRequest("POST", "/mempool/watch", strings.NewReader(body))
	req.Header.Set("X-Anvil-Auth", "test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (partial success), got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["failed"].(float64)) != 1 {
		t.Fatalf("expected 1 failed, got %v", resp["failed"])
	}
}

func TestWatchRemove(t *testing.T) {
	srv := testServerWithWatcher(t)

	// Add first
	addBody := `{"addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}`
	req := httptest.NewRequest("POST", "/mempool/watch", strings.NewReader(addBody))
	req.Header.Set("X-Anvil-Auth", "test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Remove
	rmBody := `{"addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}`
	req2 := httptest.NewRequest("DELETE", "/mempool/watch", strings.NewReader(rmBody))
	req2.Header.Set("X-Anvil-Auth", "test-token")
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w2.Body.Bytes(), &resp)
	if int(resp["watching"].(float64)) != 0 {
		t.Fatalf("expected watching=0 after remove, got %v", resp["watching"])
	}
}

func TestWatchDeleteRequiresAuth(t *testing.T) {
	srv := testServerWithWatcher(t)
	body := `{"addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}`
	req := httptest.NewRequest("DELETE", "/mempool/watch", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}
}

func TestWatchHistoryRequiresAddress(t *testing.T) {
	srv := testServerWithWatcher(t)
	req := httptest.NewRequest("GET", "/mempool/watch/history", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing address, got %d", w.Code)
	}
}

func TestWatchHistoryEmptyResult(t *testing.T) {
	srv := testServerWithWatcher(t)
	req := httptest.NewRequest("GET", "/mempool/watch/history?address=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// With nil db, history returns null/empty
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["count"].(float64)) != 0 {
		t.Fatalf("expected 0 count for empty history, got %v", resp["count"])
	}
}

func TestWatchSubscribeSSE(t *testing.T) {
	srv := testServerWithWatcher(t)

	addr := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

	// Add the address to the watch list
	addBody := `{"addresses":["` + addr + `"]}`
	addReq := httptest.NewRequest("POST", "/mempool/watch", strings.NewReader(addBody))
	addReq.Header.Set("X-Anvil-Auth", "test-token")
	addW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(addW, addReq)

	// Start SSE subscription in background
	req := httptest.NewRequest("GET", "/mempool/watch/subscribe?address="+addr, nil)
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(w, req)
		close(done)
	}()

	// Wait for SSE handler to register its subscription
	time.Sleep(50 * time.Millisecond)

	// Build a real P2PKH tx paying to the watched address's hash160.
	// Extract hash160 from the watcher's internal state.
	watchList := srv.watcher.List()
	if len(watchList) != 1 {
		t.Fatalf("expected 1 watched address, got %d", len(watchList))
	}

	// Build a minimal tx with a P2PKH output for this address.
	// We use the wire package directly (same as watcher_test.go).
	h160 := getHash160ForAddress(t, srv.watcher, addr)
	txHash, raw := buildTestP2PKHTx(h160, 42000)
	srv.watcher.CheckTx(txHash, raw)

	// Wait for SSE to flush
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Verify SSE headers
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %s", contentType)
	}

	// Verify actual event payload was delivered
	body := w.Body.String()
	if !strings.Contains(body, "data: ") {
		t.Fatalf("expected SSE data: prefix in body, got: %s", body)
	}
	if !strings.Contains(body, "id: ") {
		t.Fatalf("expected SSE id: field in body, got: %s", body)
	}
	if !strings.Contains(body, addr) {
		t.Fatalf("expected address %s in SSE payload, got: %s", addr, body)
	}
	if !strings.Contains(body, "42000") {
		t.Fatalf("expected satoshis 42000 in SSE payload, got: %s", body)
	}
}

// getHash160ForAddress extracts the hash160 bytes for a watched address.
func getHash160ForAddress(t *testing.T, w *mempool.Watcher, addr string) [20]byte {
	t.Helper()
	// Use the script package to decode, same as the watcher does internally
	a, err := script.NewAddressFromString(addr)
	if err != nil {
		t.Fatalf("decode address: %v", err)
	}
	var h [20]byte
	copy(h[:], a.PublicKeyHash)
	return h
}

// buildTestP2PKHTx creates a minimal serialized tx with one P2PKH output.
func buildTestP2PKHTx(hash160 [20]byte, satoshis int64) (chainhash.Hash, []byte) {
	tx := wire.NewMsgTx(1)
	prevHash := chainhash.Hash{}
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 0), nil))
	pkScript := make([]byte, 25)
	pkScript[0] = 0x76 // OP_DUP
	pkScript[1] = 0xa9 // OP_HASH160
	pkScript[2] = 0x14 // push 20
	copy(pkScript[3:23], hash160[:])
	pkScript[23] = 0x88 // OP_EQUALVERIFY
	pkScript[24] = 0xac // OP_CHECKSIG
	tx.AddTxOut(wire.NewTxOut(satoshis, pkScript))

	var buf []byte
	bw := &byteWriter{buf: &buf}
	tx.Serialize(bw)
	return tx.TxHash(), buf
}

type byteWriter struct{ buf *[]byte }

func (bw *byteWriter) Write(p []byte) (int, error) {
	*bw.buf = append(*bw.buf, p...)
	return len(p), nil
}

func TestWatchNoWatcherReturns503(t *testing.T) {
	// Server without watcher
	srv := testServer(t)

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/mempool/watch", `{"addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}`},
		{"DELETE", "/mempool/watch", `{"addresses":["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]}`},
		{"GET", "/mempool/watch", ""},
		{"GET", "/mempool/watch/history?address=x", ""},
		{"GET", "/mempool/watch/subscribe?address=x", ""},
	}

	for _, tc := range cases {
		var bodyReader *bytes.Reader
		if tc.body != "" {
			bodyReader = bytes.NewReader([]byte(tc.body))
		} else {
			bodyReader = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(tc.method, tc.path, bodyReader)
		if tc.method == "POST" || tc.method == "DELETE" {
			req.Header.Set("X-Anvil-Auth", "test-token")
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: expected 503 without watcher, got %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}
