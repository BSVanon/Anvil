package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// buildPaymentTx creates a minimal valid BSV transaction with an output of the given satoshis.
func buildPaymentTx(t *testing.T, satoshis uint64) (txHex, txid string) {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.Version = 1
	s, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      satoshis,
		LockingScript: s,
	})
	raw := tx.Bytes()
	return hex.EncodeToString(raw), tx.TxID().String()
}

func testServerWithPayment(t *testing.T, priceSatoshis int) *Server {
	t.Helper()
	srv := testServer(t)
	srv.paymentSatoshis = priceSatoshis
	// Re-init routes with payment gate
	srv.mux = http.NewServeMux()
	srv.routes()
	return srv
}

func TestPaymentGate402Challenge(t *testing.T) {
	srv := testServerWithPayment(t, 100)

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d: %s", w.Code, w.Body.String())
	}

	// Check challenge headers
	challengeHeader := w.Header().Get(HeaderX402Challenge)
	if challengeHeader == "" {
		t.Fatal("expected X-402-Challenge header")
	}
	priceHeader := w.Header().Get(HeaderX402Price)
	if priceHeader != "100" {
		t.Fatalf("expected X-402-Price=100, got %s", priceHeader)
	}
	networkHeader := w.Header().Get(HeaderX402Network)
	if networkHeader != "mainnet" {
		t.Fatalf("expected X-402-Network=mainnet, got %s", networkHeader)
	}

	// Parse challenge body
	var challenge PaymentChallenge
	json.NewDecoder(w.Body).Decode(&challenge)
	if challenge.Price != 100 {
		t.Fatalf("expected price=100, got %d", challenge.Price)
	}
	if challenge.Nonce == "" {
		t.Fatal("expected non-empty nonce")
	}

	t.Logf("402 challenge: nonce=%s price=%d", challenge.Nonce, challenge.Price)
}

func TestPaymentGateAcceptsValidProof(t *testing.T) {
	srv := testServerWithPayment(t, 100)

	txHex, txid := buildPaymentTx(t, 200) // pays more than required

	proof := PaymentProof{
		TxHex: txHex,
		TxID:  txid,
		Nonce: "test",
	}
	proofJSON, _ := json.Marshal(proof)

	req := httptest.NewRequest("GET", "/status", nil)
	req.Header.Set(HeaderX402Proof, string(proofJSON))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid payment, got %d: %s", w.Code, w.Body.String())
	}

	// Check receipt header
	receiptHeader := w.Header().Get(HeaderX402Receipt)
	if receiptHeader == "" {
		t.Fatal("expected X-402-Receipt header")
	}
	var receipt PaymentReceipt
	json.Unmarshal([]byte(receiptHeader), &receipt)
	if receipt.TxID != txid {
		t.Fatalf("receipt txid mismatch: %s vs %s", receipt.TxID, txid)
	}

	t.Logf("payment accepted: txid=%s satoshis=%d", receipt.TxID, receipt.Satoshis)
}

func TestPaymentGateRejectsInsufficientPayment(t *testing.T) {
	srv := testServerWithPayment(t, 1000)

	txHex, txid := buildPaymentTx(t, 100) // pays less than required

	proof := PaymentProof{TxHex: txHex, TxID: txid}
	proofJSON, _ := json.Marshal(proof)

	req := httptest.NewRequest("GET", "/status", nil)
	req.Header.Set(HeaderX402Proof, string(proofJSON))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for insufficient payment, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPaymentGateRejectsBadTxHex(t *testing.T) {
	srv := testServerWithPayment(t, 100)

	proof := PaymentProof{TxHex: "not_hex", TxID: "fake"}
	proofJSON, _ := json.Marshal(proof)

	req := httptest.NewRequest("GET", "/status", nil)
	req.Header.Set(HeaderX402Proof, string(proofJSON))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for bad txHex, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPaymentGateRejectsTxIDMismatch(t *testing.T) {
	srv := testServerWithPayment(t, 100)

	txHex, _ := buildPaymentTx(t, 200)

	proof := PaymentProof{TxHex: txHex, TxID: "0000000000000000000000000000000000000000000000000000000000000000"}
	proofJSON, _ := json.Marshal(proof)

	req := httptest.NewRequest("GET", "/status", nil)
	req.Header.Set(HeaderX402Proof, string(proofJSON))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for txid mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPaymentGateFreeWhenZeroPrice(t *testing.T) {
	srv := testServerWithPayment(t, 0) // free

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when price=0, got %d: %s", w.Code, w.Body.String())
	}
}

func TestX402DiscoveryEndpoint(t *testing.T) {
	srv := testServerWithPayment(t, 50)

	req := httptest.NewRequest("GET", "/.well-known/x402", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["network"] != "mainnet" {
		t.Fatalf("expected network=mainnet, got %v", body["network"])
	}
	if body["scheme"] != "bsv-tx-v1" {
		t.Fatalf("expected scheme=bsv-tx-v1, got %v", body["scheme"])
	}
	endpoints := body["endpoints"].([]interface{})
	if len(endpoints) == 0 {
		t.Fatal("expected non-empty endpoints list")
	}

	t.Logf("x402 discovery: %d gated endpoints at %v sats", len(endpoints), body["endpoints"].([]interface{})[0].(map[string]interface{})["price"])
}

func TestX402DiscoveryHiddenWhenFree(t *testing.T) {
	srv := testServerWithPayment(t, 0) // free — no discovery endpoint

	req := httptest.NewRequest("GET", "/.well-known/x402", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should be 404 because the route isn't registered when price=0
	if w.Code == http.StatusOK {
		t.Fatal("expected no x402 discovery when price=0")
	}
}

func TestProxyTrustFalseIgnoresXFF(t *testing.T) {
	rl := NewRateLimiter(2, false) // trust_proxy = false

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust rate limit for RemoteAddr
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1") // should be ignored
		w := httptest.NewRecorder()
		handler(w, req)
	}

	// Same RemoteAddr, different XFF — should still be limited because XFF is ignored
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.99") // different XFF
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (XFF should be ignored with trust_proxy=false), got %d", w.Code)
	}
}

func TestProxyTrustTrueUsesXFF(t *testing.T) {
	rl := NewRateLimiter(2, true) // trust_proxy = true

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust rate limit for XFF IP "10.0.0.1"
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		w := httptest.NewRecorder()
		handler(w, req)
	}

	// Different XFF IP should still be allowed
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for different XFF IP with trust_proxy=true, got %d", w.Code)
	}
}
