package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestX402DiscoveryAdvertisesBroadcast verifies /broadcast is advertised in
// /.well-known/x402 after the switch to authOrPayBinary. Machine consumers
// (AI agents, wallets with x402 clients) rely on this discovery path to find
// and price endpoints; a missing entry means they can't auto-discover that
// /broadcast accepts payment.
func TestX402DiscoveryAdvertisesBroadcast(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/.well-known/x402", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	endpoints, ok := resp["endpoints"].([]interface{})
	if !ok {
		t.Fatal("expected endpoints array in x402 discovery")
	}

	found := false
	for _, e := range endpoints {
		em, _ := e.(map[string]interface{})
		if em["method"] == "POST" && em["path"] == "/broadcast" {
			found = true
			break
		}
	}
	if !found {
		t.Error("POST /broadcast missing from /.well-known/x402 endpoints — machine consumers cannot discover the x402-paid broadcast path")
	}
}

// TestX402InfoAdvertisesBroadcast verifies the Calhooon-compatible
// /.well-known/x402-info endpoint also lists /broadcast.
func TestX402InfoAdvertisesBroadcast(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/.well-known/x402-info", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	endpoints, _ := resp["endpoints"].([]interface{})

	found := false
	for _, e := range endpoints {
		em, _ := e.(map[string]interface{})
		if em["method"] == "POST" && em["path"] == "/broadcast" {
			found = true
			break
		}
	}
	if !found {
		t.Error("POST /broadcast missing from /.well-known/x402-info endpoints")
	}
}

// TestX402DiscoveryStatsPriceUsesOwnPath verifies the Low-severity pricing bug
// is fixed: /stats discovery must use priceForPath("/stats"), not the /status
// price. Catches regression if someone reuses the wrong path constant again.
func TestX402DiscoveryStatsPriceUsesOwnPath(t *testing.T) {
	// Build a server with a per-endpoint price override so the bug is
	// observable — distinct prices for /status and /stats.
	srv := testServer(t)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &DevNonceProvider{},
		EndpointPrices: map[string]int{
			"/status": 10,
			"/stats":  50,
		},
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/.well-known/x402", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	endpoints, _ := resp["endpoints"].([]interface{})

	for _, e := range endpoints {
		em, _ := e.(map[string]interface{})
		if em["path"] == "/stats" {
			// JSON numbers decode as float64
			price, _ := em["price"].(float64)
			if int(price) != 50 {
				t.Errorf("/stats price = %v, want 50 (bug: discovery was using /status price)", price)
			}
			return
		}
	}
	t.Error("/stats not present in x402 discovery endpoints")
}
