package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/BSVanon/Anvil/pkg/brc"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
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

	return NewServer(hs, ps, es, nil, validator, broadcaster, "test-token", logger)
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
	return NewServer(hs, ps, es, nil, validator, broadcaster, "", logger) // empty token
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
	return NewServer(hs, ps, es, nil, validator, broadcaster, "test-token", logger)
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
	return NewServer(hs, ps, es, od, validator, broadcaster, "test-token", logger)
}

func overlayTestKey() *ec.PrivateKey {
	key, _ := ec.PrivateKeyFromWif("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S")
	return key
}

func TestOverlayLookupEmpty(t *testing.T) {
	srv := testServerWithOverlay(t)
	req := httptest.NewRequest("GET", "/overlay/lookup?topic=forge:mainnet", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["count"].(float64) != 0 {
		t.Fatalf("expected 0 peers, got %v", resp["count"])
	}
}

func TestOverlayLookupRequiresTopic(t *testing.T) {
	srv := testServerWithOverlay(t)
	req := httptest.NewRequest("GET", "/overlay/lookup", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestEndToEndRegisterThenLookup(t *testing.T) {
	srv := testServerWithOverlay(t)
	key := overlayTestKey()

	// Build a real SHIP script
	scriptBytes, _, err := brc.BuildSHIPScript(key, "peer.example.com:8333", "forge:mainnet")
	if err != nil {
		t.Fatal(err)
	}

	// POST /overlay/register
	body := fmt.Sprintf(`{"script":"%s","txid":"tx123","output_index":0}`, hex.EncodeToString(scriptBytes))
	req := httptest.NewRequest("POST", "/overlay/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// GET /overlay/lookup?topic=forge:mainnet should now return the peer
	req2 := httptest.NewRequest("GET", "/overlay/lookup?topic=forge:mainnet", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("lookup: expected 200, got %d", w2.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["count"].(float64) != 1 {
		t.Fatalf("expected 1 peer after registration, got %v", resp["count"])
	}

	peers := resp["peers"].([]interface{})
	peer := peers[0].(map[string]interface{})
	if peer["domain"] != "peer.example.com:8333" {
		t.Fatalf("expected domain peer.example.com:8333, got %v", peer["domain"])
	}

	t.Logf("e2e overlay success: registered SHIP -> lookup found peer at %s", peer["domain"])
}

func TestOverlayRegisterRejectsInvalid(t *testing.T) {
	srv := testServerWithOverlay(t)
	body := `{"script":"deadbeef","txid":"tx","output_index":0}`
	req := httptest.NewRequest("POST", "/overlay/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEndToEndRegisterThenDeregister(t *testing.T) {
	srv := testServerWithOverlay(t)
	key := overlayTestKey()

	scriptBytes, _, _ := brc.BuildSHIPScript(key, "temp.example.com", "forge:mainnet")

	// Register
	body := fmt.Sprintf(`{"script":"%s","txid":"tx999","output_index":0}`, hex.EncodeToString(scriptBytes))
	req := httptest.NewRequest("POST", "/overlay/register", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify it's there
	req2 := httptest.NewRequest("GET", "/overlay/lookup?topic=forge:mainnet", nil)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	var resp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp)
	if resp["count"].(float64) != 1 {
		t.Fatalf("expected 1 peer, got %v", resp["count"])
	}

	// Deregister
	identityPubHex := hex.EncodeToString(key.PubKey().Compressed())
	deregBody := fmt.Sprintf(`{"topic":"forge:mainnet","identity_pub":"%s"}`, identityPubHex)
	req3 := httptest.NewRequest("POST", "/overlay/deregister", strings.NewReader(deregBody))
	req3.Header.Set("Authorization", "Bearer test-token")
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("deregister: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	// Verify it's gone
	req4 := httptest.NewRequest("GET", "/overlay/lookup?topic=forge:mainnet", nil)
	w4 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w4, req4)
	var resp2 map[string]interface{}
	json.NewDecoder(w4.Body).Decode(&resp2)
	if resp2["count"].(float64) != 0 {
		t.Fatalf("expected 0 peers after deregister, got %v", resp2["count"])
	}

	t.Log("e2e deregister success")
}
