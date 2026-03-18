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

// testWallet creates a real NodeWallet in a temp directory for handler testing.
func testWallet(t *testing.T) *NodeWallet {
	t.Helper()

	dir, _ := os.MkdirTemp("", "anvil-wallet-handler-*")
	t.Cleanup(func() { os.RemoveAll(dir) })

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

	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, slog.Default())

	// Use a well-known test WIF (from go-sdk test fixtures)
	wif := "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"
	nw, err := New(wif, dir, hs, ps, broadcaster, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
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
