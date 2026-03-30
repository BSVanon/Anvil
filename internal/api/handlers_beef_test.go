package api

import (
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
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestGetBEEFCacheHit(t *testing.T) {
	srv := testServer(t)

	// Build a minimal valid BEEF and store it in the proof store.
	// Create a coinbase-like tx with a merkle path so it serializes as BEEF.
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})

	// Create a trivial merkle path (height 1, leaf at index 0)
	isTrue := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: tx.TxID(), Txid: &isTrue},
		{Offset: 1, Hash: tx.TxID()},
	}}
	tx.MerklePath = transaction.NewMerklePath(900000, path)

	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("build beef: %v", err)
	}
	beefBytes, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("atomic bytes: %v", err)
	}

	txid, err := srv.proofStore.StoreBEEF(beefBytes)
	if err != nil {
		t.Fatalf("store beef: %v", err)
	}

	// Request it
	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["txid"] != txid {
		t.Fatalf("txid mismatch: got %v, want %s", resp["txid"], txid)
	}
	if resp["beef"] == nil || resp["beef"] == "" {
		t.Fatal("expected non-empty beef field")
	}
}

func TestGetBEEFCacheMiss404NoFetcher(t *testing.T) {
	// testServer has no ProofFetcher configured, so cache miss → 404
	srv := testServer(t)

	fakeTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	req := httptest.NewRequest("GET", "/tx/"+fakeTxid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown txid without fetcher, got %d", w.Code)
	}
}

func TestGetBEEFInvalidTxid(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/tx/tooshort/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short txid, got %d", w.Code)
	}
}

func TestGetBEEFBinaryResponse(t *testing.T) {
	srv := testServer(t)

	// Build and store BEEF (same as cache hit test)
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      2000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})
	isTrue := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: tx.TxID(), Txid: &isTrue},
		{Offset: 1, Hash: tx.TxID()},
	}}
	tx.MerklePath = transaction.NewMerklePath(900001, path)
	beef, _ := transaction.NewBeefFromTransaction(tx)
	beefBytes, _ := beef.AtomicBytes(tx.TxID())
	txid, _ := srv.proofStore.StoreBEEF(beefBytes)

	// Request as binary
	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	req.Header.Set("Accept", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("expected octet-stream content type, got %s", w.Header().Get("Content-Type"))
	}
	if len(w.Body.Bytes()) == 0 {
		t.Fatal("expected non-empty binary body")
	}
}

func testServerWithFetcher(t *testing.T, fetcher *spv.ProofFetcher) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-beef-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-beef-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-beef-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	return NewServer(ServerConfig{
		HeaderStore:  hs,
		ProofStore:   ps,
		EnvelopeStore: es,
		Validator:    nil, // skip header validation in fetcher tests (no real headers)
		Broadcaster:  txrelay.NewBroadcaster(txrelay.NewMempool(), nil, slog.Default()),
		AuthToken:    "test-token",
		Logger:       slog.Default(),
		ProofFetcher: fetcher,
	})
}

// buildTestBeefTx creates a minimal tx with a merkle path and returns its
// raw hex, txid, and the TSC proof JSON that a mock WoC would return.
func buildTestBeefTx(t *testing.T) (rawHex string, txid string, tscJSON string, blockHeight int) {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      5000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})

	txid = tx.TxID().String()
	rawHex = hex.EncodeToString(tx.Bytes())
	blockHeight = 900100

	// Build a trivial TSC proof: the tx is the only leaf
	// TSC format: [{index, txOrId, target, nodes: ["*"]}]
	tscJSON = fmt.Sprintf(`[{"index":0,"txOrId":"%s","target":"","nodes":["*"]}]`, txid)
	return
}

func TestGetBEEFFetcherEnabledCacheMiss(t *testing.T) {
	rawHex, txid, tscJSON, blockHeight := buildTestBeefTx(t)

	// Mock WoC server
	mockWoC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/hex"):
			w.Write([]byte(rawHex))
		case strings.HasSuffix(r.URL.Path, "/proof/tsc"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(tscJSON))
		default:
			// tx info endpoint
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"blockheight":%d}`, blockHeight)
		}
	}))
	defer mockWoC.Close()

	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mockWoC.URL)

	srv := testServerWithFetcher(t, fetcher)

	// First request: cache miss → fetcher builds BEEF
	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for fetcher-enabled cache miss, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["txid"] != txid {
		t.Fatalf("txid mismatch: got %v, want %s", resp["txid"], txid)
	}
	if resp["beef"] == nil || resp["beef"] == "" {
		t.Fatal("expected non-empty beef in response")
	}

	// Second request: should be a cache hit now (proof was stored)
	if !srv.proofStore.HasBEEF(txid) {
		t.Fatal("expected BEEF to be cached in proof store after fetch")
	}
}

func TestGetBEEFFetcherUnconfirmed404(t *testing.T) {
	rawHex, txid, _, _ := buildTestBeefTx(t)

	// Mock WoC: tx exists but is unconfirmed (blockheight = 0)
	mockWoC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/hex"):
			w.Write([]byte(rawHex))
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"blockheight":0}`)
		}
	}))
	defer mockWoC.Close()

	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mockWoC.URL)

	srv := testServerWithFetcher(t, fetcher)

	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unconfirmed tx, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetBEEFFetcherTxNotFound404(t *testing.T) {
	// Mock WoC: tx doesn't exist
	mockWoC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer mockWoC.Close()

	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mockWoC.URL)

	srv := testServerWithFetcher(t, fetcher)

	fakeTxid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	req := httptest.NewRequest("GET", "/tx/"+fakeTxid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent tx, got %d: %s", w.Code, w.Body.String())
	}
}

func mustDecodeScript(t *testing.T, h string) *bsvscript.Script {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	s := bsvscript.Script(b)
	return &s
}
