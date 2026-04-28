package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	p2pchainhash "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

func testServer(t *testing.T) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-api-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	validator := spv.NewValidator(hs)
	logger := slog.Default()
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, logger)
	edir, _ := os.MkdirTemp("", "anvil-api-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	return NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es,
		Validator: validator, Broadcaster: broadcaster, AuthToken: "test-token", Logger: logger,
	})
}

// testServerNoAuth creates a server with no auth token configured.
func testServerNoAuth(t *testing.T) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-api-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-api-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	validator := spv.NewValidator(hs)
	logger := slog.Default()
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, logger)
	return NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es,
		Validator: validator, Broadcaster: broadcaster, Logger: logger,
	}) // empty token
}

// --- Open read endpoints ---

func TestStatusEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["node"] != "anvil" {
		t.Fatalf("expected node=anvil, got %v", resp["node"])
	}
	h := resp["headers"].(map[string]interface{})
	if h["height"].(float64) != 0 {
		t.Fatalf("expected height 0, got %v", h["height"])
	}
}

func TestStatusIncludesSPVAndSyncDetails(t *testing.T) {
	srv := testServer(t)
	srv.headerSyncStatus = func() headers.SyncStats {
		return headers.SyncStats{
			LastSource:    "seed.bitcoinsv.io:8333",
			LastAttemptAt: "2026-03-29T01:00:00Z",
			LastSuccessAt: "2026-03-29T01:00:02Z",
			LastTip:       100,
		}
	}
	srv.spvProofSource = "arc+woc-fallback"

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	headersInfo := resp["headers"].(map[string]interface{})
	if headersInfo["sync_lag_secs"] == nil {
		t.Fatal("expected sync_lag_secs in headers")
	}
	syncInfo := headersInfo["sync"].(map[string]interface{})
	if syncInfo["last_source"] != "seed.bitcoinsv.io:8333" {
		t.Fatalf("expected last_source in sync info, got %v", syncInfo["last_source"])
	}

	spvInfo := resp["spv"].(map[string]interface{})
	if spvInfo["proof_source"] != "arc+woc-fallback" {
		t.Fatalf("expected proof_source, got %v", spvInfo["proof_source"])
	}
}

func TestHeadersTipEndpoint(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/headers/tip", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["height"].(float64) != 0 {
		t.Fatalf("expected height 0, got %v", resp["height"])
	}
	if resp["hash"] == nil || resp["hash"] == "" {
		t.Fatal("expected non-empty hash")
	}
}

// addServerTestChain appends n synthetic headers (heights 1..n) onto the
// server's header store, returning the new tip height.
func addServerTestChain(t *testing.T, srv *Server, n int) uint32 {
	t.Helper()
	prevHash, _ := srv.headerStore.HashAtHeight(0)
	merkle, err := p2pchainhash.NewHashFromStr("abcdef0000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	hdrs := make([]*wire.BlockHeader, 0, n)
	for i := 0; i < n; i++ {
		hdr := wire.NewBlockHeader(1, prevHash, merkle, 0x1d00ffff, uint32(i))
		hdrs = append(hdrs, hdr)
		h := hdr.BlockHash()
		prevHash = &h
	}
	if err := srv.headerStore.AddHeaders(1, hdrs); err != nil {
		t.Fatal(err)
	}
	return uint32(n)
}

func TestHeadersRangeJSON(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 10)

	req := httptest.NewRequest("GET", "/headers/range?from=2&count=3", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["from"].(float64) != 2 || resp["count"].(float64) != 3 || resp["tipHeight"].(float64) != 10 {
		t.Fatalf("bad response shape: %+v", resp)
	}
	hdrs := resp["headers"].([]interface{})
	if len(hdrs) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(hdrs))
	}
	for i, h := range hdrs {
		raw, err := hex.DecodeString(h.(string))
		if err != nil {
			t.Fatalf("header %d: hex decode: %v", i, err)
		}
		if len(raw) != 80 {
			t.Fatalf("header %d: expected 80 bytes, got %d", i, len(raw))
		}
	}
}

func TestHeadersRangeBinary(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 10)

	req := httptest.NewRequest("GET", "/headers/range?from=1&count=3", nil)
	req.Header.Set("Accept", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("expected octet-stream, got %s", ct)
	}
	body := w.Body.Bytes()
	if len(body) != 240 {
		t.Fatalf("expected 240 bytes, got %d", len(body))
	}
	// Verify chain link inside the binary blob.
	var h1, h2 wire.BlockHeader
	if err := h1.Deserialize(bytes.NewReader(body[0:80])); err != nil {
		t.Fatal(err)
	}
	if err := h2.Deserialize(bytes.NewReader(body[80:160])); err != nil {
		t.Fatal(err)
	}
	expectedPrev := h1.BlockHash()
	if h2.PrevBlock != expectedPrev {
		t.Fatal("chain link broken in binary range")
	}
}

func TestHeadersRangeExceedsTip(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 5)

	req := httptest.NewRequest("GET", "/headers/range?from=4&count=10", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["tipHeight"].(float64) != 5 {
		t.Fatalf("expected tipHeight 5 in error body, got %v", resp["tipHeight"])
	}
}

func TestHeadersRangeBadParams(t *testing.T) {
	srv := testServer(t)
	cases := []string{
		"/headers/range",                   // missing both
		"/headers/range?from=0",            // missing count
		"/headers/range?count=3",           // missing from
		"/headers/range?from=abc&count=3",  // non-integer from
		"/headers/range?from=0&count=abc",  // non-integer count
		"/headers/range?from=0&count=0",    // count < 1
		"/headers/range?from=0&count=51",   // count > MAX
		"/headers/range?from=-1&count=3",   // negative from
	}
	for _, path := range cases {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", path, w.Code)
		}
	}
}

func TestHeadersRangeMaxBoundary(t *testing.T) {
	srv := testServer(t)
	addServerTestChain(t, srv, 60)

	req := httptest.NewRequest("GET", "/headers/range?from=1&count=50", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("count=50 (boundary) should succeed, got %d", w.Code)
	}
}

func TestGetBEEFNotFound(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/tx/0000000000000000000000000000000000000000000000000000000000000000/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetBEEFBadTxid(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("GET", "/tx/short/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- Auth ---

func TestBroadcastRequiresAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestBroadcastWithValidAuth(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("garbage"))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should not be 401 — will be 422 due to invalid BEEF
	if w.Code == http.StatusUnauthorized {
		t.Fatal("should not be 401 with valid token")
	}
}

func TestBroadcastRejectsInvalidBEEF(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("not beef at all"))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}

	var resp BroadcastResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Confidence != spv.ConfidenceInvalid {
		t.Fatalf("expected confidence=invalid, got %s", resp.Confidence)
	}
}

func TestBroadcastReturnsStructuredResponse(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("bad beef"))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var resp BroadcastResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Confidence == "" {
		t.Fatal("expected a confidence level in the response")
	}
	if resp.TxID != "" && resp.Confidence != spv.ConfidenceInvalid {
		// If valid, structured fields should be present
		t.Logf("txid=%s confidence=%s stored=%v mempool=%v", resp.TxID, resp.Confidence, resp.Stored, resp.Mempool)
	}
}

// --- Auth default: no token = writes disabled ---

func TestBroadcastDisabledWithNoToken(t *testing.T) {
	srv := testServerNoAuth(t)
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader("anything"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when no auth token configured, got %d", w.Code)
	}
}

// --- JSON body parsing ---

func TestBroadcastAcceptsJSON(t *testing.T) {
	srv := testServer(t)
	body := `{"beef": "deadbeef"}`
	req := httptest.NewRequest("POST", "/broadcast", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should parse the JSON and attempt to validate the hex
	// deadbeef is not valid BEEF, so expect 422
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBroadcastEmptyBody(t *testing.T) {
	srv := testServer(t)
	req := httptest.NewRequest("POST", "/broadcast", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", w.Code)
	}
}

// --- End-to-end: POST /broadcast -> GET /tx/{txid}/beef ---

// gullibleTracker accepts any merkle root for end-to-end testing.
type gullibleTracker struct{}

func (g *gullibleTracker) IsValidRootForHeight(_ context.Context, _ *chainhash.Hash, _ uint32) (bool, error) {
	return true, nil
}
func (g *gullibleTracker) CurrentHeight(_ context.Context) (uint32, error) {
	return 999999, nil
}

func testServerGullible(t *testing.T) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-api-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-api-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	// Use gullible tracker so BUMP verification always succeeds
	validator := spv.NewValidator(&gullibleTracker{})
	logger := slog.Default()
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, logger)
	return NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es,
		Validator: validator, Broadcaster: broadcaster, AuthToken: "test-token", Logger: logger,
	})
}

func buildTestBEEF(t *testing.T) []byte {
	t.Helper()
	parent := transaction.NewTransaction()
	parent.Version = 1
	s, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	parent.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: s,
	})
	txidHash := parent.TxID()
	boolTrue := true
	parent.MerklePath = transaction.NewMerklePath(100, [][]*transaction.PathElement{
		{
			{Offset: 0, Hash: txidHash, Txid: &boolTrue},
			{Offset: 1, Duplicate: &boolTrue},
		},
	})
	child := transaction.NewTransaction()
	child.Version = 1
	child.AddInput(&transaction.TransactionInput{
		SourceTXID:        txidHash,
		SourceTxOutIndex:  0,
		SequenceNumber:    0xffffffff,
		SourceTransaction: parent,
	})
	s2, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	child.AddOutput(&transaction.TransactionOutput{
		Satoshis:      900,
		LockingScript: s2,
	})
	beefBytes, err := child.BEEF()
	if err != nil {
		t.Fatalf("encode BEEF: %v", err)
	}
	return beefBytes
}

func TestEndToEndBroadcastThenRetrieve(t *testing.T) {
	srv := testServerGullible(t)
	beefBytes := buildTestBEEF(t)

	// POST /broadcast with valid BEEF
	req := httptest.NewRequest("POST", "/broadcast", bytes.NewReader(beefBytes))
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("broadcast: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp BroadcastResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.TxID == "" {
		t.Fatal("expected non-empty txid")
	}
	if resp.Confidence != spv.ConfidenceSPVVerified {
		t.Fatalf("expected spv_verified, got %s", resp.Confidence)
	}
	if !resp.Stored {
		t.Fatal("expected stored=true for verified BEEF")
	}
	if !resp.Mempool {
		t.Fatal("expected mempool=true")
	}

	// GET /tx/{txid}/beef should return the stored BEEF
	req2 := httptest.NewRequest("GET", "/tx/"+resp.TxID+"/beef", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("get beef: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var beefResp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&beefResp)
	if beefResp["txid"] != resp.TxID {
		t.Fatalf("expected txid %s, got %v", resp.TxID, beefResp["txid"])
	}
	if beefResp["beef"] == nil || beefResp["beef"] == "" {
		t.Fatal("expected non-empty beef hex in response")
	}

	t.Logf("e2e success: txid=%s confidence=%s stored=%v", resp.TxID, resp.Confidence, resp.Stored)
}

// --- Overlay tests ---

func testServerWithOverlay(t *testing.T) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-api-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, _ := headers.NewTestStore(hdir)
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-api-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, _ := spv.NewProofStore(pdir)
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-api-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	odir, _ := os.MkdirTemp("", "anvil-api-overlay-*")
	t.Cleanup(func() { os.RemoveAll(odir) })
	od, _ := overlay.NewDirectory(odir)
	t.Cleanup(func() { od.Close() })

	validator := spv.NewValidator(hs)
	logger := slog.Default()
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, logger)
	return NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es, OverlayDir: od,
		Validator: validator, Broadcaster: broadcaster, AuthToken: "test-token", Logger: logger,
	})
}

func overlayTestKey() *ec.PrivateKey {
	key, _ := ec.PrivateKeyFromWif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S")
	return key
}

