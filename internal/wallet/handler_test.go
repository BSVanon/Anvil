package wallet

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
)

const testWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"

// testInfra holds shared infrastructure that outlives a single NodeWallet instance.
type testInfra struct {
	hdir string
	pdir string
	hs   *headers.Store
	ps   *spv.ProofStore
}

func newTestInfra(t *testing.T) *testInfra {
	t.Helper()
	hdir, _ := os.MkdirTemp("", "anvil-wallet-hdr-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-wallet-proof-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	return &testInfra{hdir: hdir, pdir: pdir, hs: hs, ps: ps}
}

// openWallet creates a NodeWallet in the given dataDir, backed by the shared infra.
// Caller is responsible for closing it.
func (ti *testInfra) openWallet(t *testing.T, dataDir string) *NodeWallet {
	t.Helper()
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, slog.Default())
	nw, err := New(testWIF, dataDir, ti.hs, ti.ps, broadcaster, nil, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return nw
}

// testWallet creates a real NodeWallet in a temp directory for handler testing.
func testWallet(t *testing.T) *NodeWallet {
	t.Helper()
	dir, _ := os.MkdirTemp("", "anvil-wallet-handler-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	ti := newTestInfra(t)
	nw := ti.openWallet(t, dir)
	t.Cleanup(func() { nw.Close() })
	return nw
}

// testMux creates an http.ServeMux with wallet routes registered (no auth middleware).
func testMux(t *testing.T) (*http.ServeMux, *NodeWallet) {
	t.Helper()
	nw := testWallet(t)
	mux := http.NewServeMux()
	nw.RegisterRoutes(mux, func(next http.HandlerFunc) http.HandlerFunc { return next })
	return mux, nw
}

func TestPostInvoiceNoCounterparty(t *testing.T) {
	mux, _ := testMux(t)

	body := `{"description":"test payment"}`
	req := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil || resp["id"] == "" {
		t.Fatal("expected non-empty invoice id")
	}
	if resp["address"] == nil || resp["address"] == "" {
		t.Fatal("expected non-empty address")
	}
	if resp["public_key"] == nil || resp["public_key"] == "" {
		t.Fatal("expected non-empty public_key")
	}

	t.Logf("invoice created: id=%v address=%v", resp["id"], resp["address"])
}

func TestPostInvoiceWithCounterparty(t *testing.T) {
	mux, _ := testMux(t)

	// Use a valid compressed pubkey (33 bytes hex = 66 chars)
	body := `{"counterparty":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","description":"from alice"}`
	req := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Fatal("expected invoice id")
	}

	t.Logf("invoice with counterparty: id=%v", resp["id"])
}

func TestPostInvoiceBadCounterparty(t *testing.T) {
	mux, _ := testMux(t)

	body := `{"counterparty":"notahexkey"}`
	req := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetInvoiceAfterCreate(t *testing.T) {
	mux, _ := testMux(t)

	// Create an invoice
	body := `{"description":"lookup test"}`
	req := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var createResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&createResp)
	id := createResp["id"].(string)
	createdAddr := createResp["address"].(string)

	// Lookup the invoice
	req2 := httptest.NewRequest("GET", "/wallet/invoice/"+id, nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("lookup: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var lookupResp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&lookupResp)
	if lookupResp["id"] != id {
		t.Fatalf("expected id=%s, got %v", id, lookupResp["id"])
	}
	if lookupResp["address"] != createdAddr {
		t.Fatalf("expected address=%s, got %v", createdAddr, lookupResp["address"])
	}
	if lookupResp["paid"] != false {
		t.Fatal("expected paid=false for unfunded invoice")
	}
	// When not paid, txid and amount should be absent
	if _, hasTxid := lookupResp["txid"]; hasTxid {
		t.Fatal("txid should be absent when not paid")
	}

	t.Logf("invoice lookup: id=%s address=%v paid=%v", id, lookupResp["address"], lookupResp["paid"])
}

func TestGetInvoiceNotFound(t *testing.T) {
	mux, _ := testMux(t)

	req := httptest.NewRequest("GET", "/wallet/invoice/999999", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUniqueInvoiceAddresses(t *testing.T) {
	mux, _ := testMux(t)

	// Create two invoices with the same counterparty — they should get different addresses
	body := `{"description":"invoice A"}`
	req1 := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	var r1, r2 map[string]interface{}
	json.NewDecoder(w1.Body).Decode(&r1)
	json.NewDecoder(w2.Body).Decode(&r2)

	if r1["address"] == r2["address"] {
		t.Fatalf("two invoices should have different addresses, both got %v", r1["address"])
	}
	if r1["id"] == r2["id"] {
		t.Fatalf("two invoices should have different IDs, both got %v", r1["id"])
	}

	t.Logf("unique addresses: %v vs %v", r1["address"], r2["address"])
}

func TestPostSendBadRequest(t *testing.T) {
	mux, _ := testMux(t)

	// Missing required fields
	body := `{"description":"bad send"}`
	req := httptest.NewRequest("POST", "/wallet/send", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing to/satoshis, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListOutputsOnFreshWallet(t *testing.T) {
	mux, _ := testMux(t)

	req := httptest.NewRequest("GET", "/wallet/outputs", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	t.Logf("list outputs on fresh wallet: status=%d", w.Code)
}

// TestInvoiceSurvivesRestart proves the full lifecycle:
// 1. Open NodeWallet, create invoice via HTTP, close wallet
// 2. Open a new NodeWallet on the same data dir
// 3. GET /wallet/invoice/:id returns 200 with the same address
// 4. GET /wallet/outputs returns 200 (not 500)
func TestInvoiceSurvivesRestart(t *testing.T) {
	dataDir, _ := os.MkdirTemp("", "anvil-wallet-restart-*")
	t.Cleanup(func() { os.RemoveAll(dataDir) })
	ti := newTestInfra(t)

	// --- First lifecycle: create an invoice ---
	nw1 := ti.openWallet(t, dataDir)
	mux1 := http.NewServeMux()
	nw1.RegisterRoutes(mux1, func(next http.HandlerFunc) http.HandlerFunc { return next })

	body := `{"description":"restart proof"}`
	req := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux1.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("create: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var createResp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&createResp)
	invoiceID := createResp["id"].(string)
	invoiceAddr := createResp["address"].(string)

	t.Logf("created invoice %s -> %s, closing wallet", invoiceID, invoiceAddr)
	nw1.Close()

	// --- Second lifecycle: reopen and look up ---
	nw2 := ti.openWallet(t, dataDir)
	defer nw2.Close()
	mux2 := http.NewServeMux()
	nw2.RegisterRoutes(mux2, func(next http.HandlerFunc) http.HandlerFunc { return next })

	// GET /wallet/invoice/:id must return 200 with the same address
	req2 := httptest.NewRequest("GET", "/wallet/invoice/"+invoiceID, nil)
	w2 := httptest.NewRecorder()
	mux2.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("lookup after restart: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var lookupResp map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&lookupResp)
	if lookupResp["id"] != invoiceID {
		t.Fatalf("expected id=%s after restart, got %v", invoiceID, lookupResp["id"])
	}
	if lookupResp["address"] != invoiceAddr {
		t.Fatalf("expected address=%s after restart, got %v", invoiceAddr, lookupResp["address"])
	}
	if lookupResp["paid"] != false {
		t.Fatal("expected paid=false after restart")
	}

	// GET /wallet/outputs must return 200, not 500
	req3 := httptest.NewRequest("GET", "/wallet/outputs", nil)
	w3 := httptest.NewRecorder()
	mux2.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("list outputs after restart: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}

	// Invoice counter must have recovered — new invoice gets a higher ID
	body2 := `{"description":"post-restart invoice"}`
	req4 := httptest.NewRequest("POST", "/wallet/invoice", strings.NewReader(body2))
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	mux2.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("create after restart: expected 200, got %d: %s", w4.Code, w4.Body.String())
	}
	var create2Resp map[string]interface{}
	json.NewDecoder(w4.Body).Decode(&create2Resp)
	newID := create2Resp["id"].(string)
	if newID <= invoiceID {
		t.Fatalf("post-restart invoice ID %s should be > pre-restart ID %s", newID, invoiceID)
	}

	t.Logf("restart proof: invoice %s survived, new invoice got ID %s, all reads 200", invoiceID, newID)
}
