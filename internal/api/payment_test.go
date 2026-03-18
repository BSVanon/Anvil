package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// testPayeeScript returns a P2PKH locking script for testing.
func testPayeeScript(t *testing.T) string {
	t.Helper()
	addr, _ := script.NewAddressFromString("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	ls, _ := script.NewFromHex("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac")
	if addr != nil {
		// use the real script
		_ = ls
	}
	return "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac"
}

// testGate creates a PaymentGate with dev nonces and a known payee script.
func testGate(t *testing.T, priceSats int) *PaymentGate {
	t.Helper()
	return NewPaymentGate(PaymentGateConfig{
		PriceSats:      priceSats,
		PayeeScriptHex: testPayeeScript(t),
	})
}

// testServerWithPaymentGate creates a Server with a spec-compliant payment gate.
func testServerWithPaymentGate(t *testing.T, priceSats int) *Server {
	t.Helper()
	srv := testServer(t)
	srv.paymentGate = testGate(t, priceSats)
	srv.mux = http.NewServeMux()
	srv.routes()
	return srv
}

// getChallenge makes a request and extracts the 402 challenge.
func getChallenge(t *testing.T, srv *Server, method, path string) *X402Challenge {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d: %s", w.Code, w.Body.String())
	}
	var ch X402Challenge
	json.NewDecoder(w.Body).Decode(&ch)
	return &ch
}

// buildProof builds a spec-compliant X402Proof for a given challenge.
func buildProof(t *testing.T, challenge *X402Challenge, payeeSats uint64, payeeScriptHex string) string {
	t.Helper()

	// Build a tx that spends the nonce UTXO and pays the payee
	tx := transaction.NewTransaction()
	tx.Version = 1

	// Input: spend the nonce UTXO
	nonceTxIDHash, _ := chainhash.NewHashFromHex(challenge.NonceUTXO.TxID)
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       nonceTxIDHash,
		SourceTxOutIndex: uint32(challenge.NonceUTXO.Vout),
		SequenceNumber:   0xffffffff,
	})

	// Output: pay the payee
	payeeScript, _ := hex.DecodeString(payeeScriptHex)
	ls := script.Script(payeeScript)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      payeeSats,
		LockingScript: &ls,
	})

	rawBytes := tx.Bytes()
	txid := tx.TxID().String()

	// Compute challenge hash
	challengeJSON, _ := json.Marshal(challenge)
	challengeHash := sha256Hex(challengeJSON)

	proof := X402Proof{
		V:               1,
		Scheme:          "bsv-tx-v1",
		ChallengeSHA256: challengeHash,
		Request: ProofRequest{
			Method:           challenge.Method,
			Path:             challenge.Path,
			Query:            challenge.Query,
			ReqHeadersSHA256: challenge.ReqHeadersSHA256,
			ReqBodySHA256:    challenge.ReqBodySHA256,
		},
		Payment: ProofPayment{
			TxID:     txid,
			RawTxB64: base64.StdEncoding.EncodeToString(rawBytes),
		},
	}

	proofJSON, _ := json.Marshal(proof)
	return base64Url(proofJSON)
}

// --- Tests ---

func TestX402ChallengeIssuedOn402(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	ch := getChallenge(t, srv, "GET", "/status")

	if ch.V != 1 {
		t.Fatalf("expected v=1, got %d", ch.V)
	}
	if ch.Scheme != "bsv-tx-v1" {
		t.Fatalf("expected scheme=bsv-tx-v1, got %s", ch.Scheme)
	}
	if ch.AmountSats != 100 {
		t.Fatalf("expected amount_sats=100, got %d", ch.AmountSats)
	}
	if ch.NonceUTXO == nil {
		t.Fatal("expected nonce_utxo in challenge")
	}
	if ch.PayeeLockingScriptHex == "" {
		t.Fatal("expected payee_locking_script_hex in challenge")
	}
	if ch.Method != "GET" {
		t.Fatalf("expected method=GET, got %s", ch.Method)
	}
	if ch.Path != "/status" {
		t.Fatalf("expected path=/status, got %s", ch.Path)
	}
	if ch.ExpiresAt <= time.Now().Unix() {
		t.Fatal("expected future expires_at")
	}

	t.Logf("challenge: nonce=%s:%d price=%d expires=%d",
		ch.NonceUTXO.TxID[:16], ch.NonceUTXO.Vout, ch.AmountSats, ch.ExpiresAt)
}

func TestX402AcceptsValidProofWithPayeeBinding(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	payeeScript := testPayeeScript(t)

	// Get challenge
	ch := getChallenge(t, srv, "GET", "/status")

	// Build proof that pays the right payee
	proofB64 := buildProof(t, ch, 200, payeeScript)

	// Retry with proof
	req := httptest.NewRequest("GET", "/status", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	receiptB64 := w.Header().Get(HeaderX402Receipt)
	if receiptB64 == "" {
		t.Fatal("expected X402-Receipt header")
	}
	t.Logf("payment accepted with payee binding")
}

func TestX402RejectsWrongPayee(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)

	ch := getChallenge(t, srv, "GET", "/status")

	// Build proof that pays a DIFFERENT script (not the node's payee)
	wrongPayee := "76a914000000000000000000000000000000000000000088ac"
	proofB64 := buildProof(t, ch, 200, wrongPayee)

	req := httptest.NewRequest("GET", "/status", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for wrong payee, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("correctly rejected payment to wrong payee")
}

func TestX402RejectsInsufficientPayment(t *testing.T) {
	srv := testServerWithPaymentGate(t, 1000)
	payeeScript := testPayeeScript(t)

	ch := getChallenge(t, srv, "GET", "/status")
	proofB64 := buildProof(t, ch, 50, payeeScript) // pays 50, needs 1000

	req := httptest.NewRequest("GET", "/status", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for insufficient payment, got %d: %s", w.Code, w.Body.String())
	}
}

func TestX402RejectsReplayedProof(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	payeeScript := testPayeeScript(t)

	ch := getChallenge(t, srv, "GET", "/status")
	proofB64 := buildProof(t, ch, 200, payeeScript)

	// First use succeeds
	req1 := httptest.NewRequest("GET", "/status", nil)
	req1.Host = "localhost"
	req1.Header.Set(HeaderX402Proof, proofB64)
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first use: expected 200, got %d", w1.Code)
	}

	// Second use (replay) must fail — challenge was consumed
	req2 := httptest.NewRequest("GET", "/status", nil)
	req2.Host = "localhost"
	req2.Header.Set(HeaderX402Proof, proofB64)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusPaymentRequired {
		t.Fatalf("replay: expected 402, got %d: %s", w2.Code, w2.Body.String())
	}
	t.Log("correctly rejected replayed proof")
}

func TestX402RejectsWrongPath(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	payeeScript := testPayeeScript(t)

	// Get challenge for /status
	ch := getChallenge(t, srv, "GET", "/status")
	proofB64 := buildProof(t, ch, 200, payeeScript)

	// Try to use it on /headers/tip — different path
	req := httptest.NewRequest("GET", "/headers/tip", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for wrong path, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("correctly rejected proof for wrong path")
}

func TestX402RejectsUnknownChallenge(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)

	// Build a proof with a fake challenge hash
	proof := X402Proof{
		V:               1,
		Scheme:          "bsv-tx-v1",
		ChallengeSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		Request:         ProofRequest{Method: "GET", Path: "/status"},
		Payment:         ProofPayment{TxID: "fake", RawTxB64: "AAAA"},
	}
	proofJSON, _ := json.Marshal(proof)

	req := httptest.NewRequest("GET", "/status", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, base64Url(proofJSON))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for unknown challenge, got %d: %s", w.Code, w.Body.String())
	}
}

func TestX402FreeWhenZeroPrice(t *testing.T) {
	srv := testServer(t) // default: no payment gate

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when price=0, got %d", w.Code)
	}
}

func TestX402DiscoveryEndpoint(t *testing.T) {
	srv := testServerWithPaymentGate(t, 50)

	req := httptest.NewRequest("GET", "/.well-known/x402", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["scheme"] != "bsv-tx-v1" {
		t.Fatalf("expected scheme=bsv-tx-v1, got %v", body["scheme"])
	}
	endpoints := body["endpoints"].([]interface{})
	if len(endpoints) == 0 {
		t.Fatal("expected gated endpoints")
	}
	first := endpoints[0].(map[string]interface{})
	if first["price"].(float64) != 50 {
		t.Fatalf("expected price=50, got %v", first["price"])
	}
}

func TestX402DiscoveryHiddenWhenFree(t *testing.T) {
	srv := testServer(t) // no payment gate

	req := httptest.NewRequest("GET", "/.well-known/x402", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("expected no discovery endpoint when free")
	}
}

func TestX402ChallengeBindsToRequest(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)

	ch1 := getChallenge(t, srv, "GET", "/status")
	ch2 := getChallenge(t, srv, "GET", "/data")

	if ch1.Path == ch2.Path {
		t.Fatal("challenges for different paths should differ")
	}
	if ch1.NonceUTXO.TxID == ch2.NonceUTXO.TxID {
		t.Fatal("challenges should have different nonce UTXOs")
	}

	// Verify challenge JSON hashes differ
	j1, _ := json.Marshal(ch1)
	j2, _ := json.Marshal(ch2)
	if sha256Hex(j1) == sha256Hex(j2) {
		t.Fatal("challenge hashes should differ for different requests")
	}
}

func TestProxyTrustFalseIgnoresXFF(t *testing.T) {
	rl := NewRateLimiter(2, false)
	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		w := httptest.NewRecorder()
		handler(w, req)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (XFF ignored), got %d", w.Code)
	}
}

func TestProxyTrustTrueUsesXFF(t *testing.T) {
	rl := NewRateLimiter(2, true)
	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		w := httptest.NewRecorder()
		handler(w, req)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for different XFF IP, got %d", w.Code)
	}
}

func TestPaymentGateNilIsNoOp(t *testing.T) {
	var pg *PaymentGate // nil
	called := false
	handler := pg.Middleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if !called {
		t.Fatal("nil gate should pass through")
	}
}

// helper to suppress unused import
var _ = fmt.Sprintf
