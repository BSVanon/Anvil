package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// appPayeeScript returns a distinct P2PKH script for the "app" (not the node).
func appPayeeScript() string {
	return "76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac"
}

// testGateWithAppPayments creates a PaymentGate with app monetization enabled
// and a resolver backed by the given envelope store.
func testGateWithAppPayments(t *testing.T, priceSats int, es *envelope.Store) *PaymentGate {
	t.Helper()
	resolver := NewTopicMonetizationResolver(es)
	return NewPaymentGate(PaymentGateConfig{
		PriceSats:        priceSats,
		PayeeScriptHex:   testPayeeScript(t),
		NonceProvider:    &DevNonceProvider{},
		Resolver:         resolver,
		AllowPassthrough: true,
		AllowSplit:       true,
	})
}

// seedEnvelope injects a signed envelope with the given monetization into the store.
func seedEnvelope(t *testing.T, es *envelope.Store, topic string, mon *envelope.Monetization) {
	t.Helper()
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:         "data",
		Topic:        topic,
		Payload:      `{"test": true}`,
		TTL:          0,
		Durable:      true,
		Timestamp:    time.Now().Unix(),
		Monetization: mon,
	}
	env.Sign(key)
	if err := es.Ingest(env); err != nil {
		t.Fatalf("seed envelope: %v", err)
	}
}

// buildMultiPayeeProof builds a proof tx that pays multiple payees.
func buildMultiPayeeProof(t *testing.T, challenge *X402Challenge, payees []Payee) string {
	t.Helper()

	tx := transaction.NewTransaction()
	tx.Version = 1

	// Input: spend the nonce UTXO
	nonceTxIDHash, _ := chainhash.NewHashFromHex(challenge.NonceUTXO.TxID)
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       nonceTxIDHash,
		SourceTxOutIndex: uint32(challenge.NonceUTXO.Vout),
		SequenceNumber:   0xffffffff,
	})

	// Outputs: one per payee
	for _, p := range payees {
		scriptBytes, _ := hex.DecodeString(p.LockingScriptHex)
		ls := script.Script(scriptBytes)
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      uint64(p.AmountSats),
			LockingScript: &ls,
		})
	}

	rawBytes := tx.Bytes()
	txid := tx.TxID().String()

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
			RawTxB64: hex.EncodeToString(rawBytes), // hex fallback
		},
	}

	proofJSON, _ := json.Marshal(proof)
	return base64Url(proofJSON)
}

// --- Passthrough (Model 2) Tests ---

func TestPassthroughChallengeUsesAppPayee(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "oracle:rates", &envelope.Monetization{
		Model:                 envelope.MonetizationPassthrough,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             50,
	})

	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	// Request data for the passthrough topic
	ch := getChallenge(t, srv, "GET", "/data?topic=oracle:rates")

	// Challenge should use the APP's payee script, not the node's
	if ch.PayeeLockingScriptHex != appPayeeScript() {
		t.Fatalf("expected app payee script %s, got %s", appPayeeScript(), ch.PayeeLockingScriptHex)
	}
	if ch.AmountSats != 50 {
		t.Fatalf("expected app price 50, got %d", ch.AmountSats)
	}
	// Should NOT have multi-payee list (single payee = app only)
	if len(ch.Payees) != 0 {
		t.Fatalf("expected no explicit Payees for passthrough (single payee), got %d", len(ch.Payees))
	}
}

func TestPassthroughAcceptsPaymentToApp(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "oracle:rates", &envelope.Monetization{
		Model:                 envelope.MonetizationPassthrough,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             50,
	})

	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	ch := getChallenge(t, srv, "GET", "/data?topic=oracle:rates")

	// Build proof paying the app (not the node)
	proofB64 := buildProof(t, ch, 50, appPayeeScript())

	req := httptest.NewRequest("GET", "/data?topic=oracle:rates", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid passthrough payment, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("passthrough payment to app accepted — node never touched funds")
}

// --- Split (Model 3) Tests ---

func TestSplitChallengeIncludesBothPayees(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "oracle:premium", &envelope.Monetization{
		Model:                 envelope.MonetizationSplit,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             50,
	})

	srv.paymentGate = testGateWithAppPayments(t, 10, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	ch := getChallenge(t, srv, "GET", "/data?topic=oracle:premium")

	// Total should be node (10) + app (50) = 60
	if ch.AmountSats != 60 {
		t.Fatalf("expected total 60, got %d", ch.AmountSats)
	}
	if len(ch.Payees) != 2 {
		t.Fatalf("expected 2 payees, got %d", len(ch.Payees))
	}

	// Check roles
	roles := map[string]int{}
	for _, p := range ch.Payees {
		roles[p.Role] = p.AmountSats
	}
	if roles["infrastructure"] != 10 {
		t.Fatalf("expected infrastructure=10, got %d", roles["infrastructure"])
	}
	if roles["content"] != 50 {
		t.Fatalf("expected content=50, got %d", roles["content"])
	}
}

func TestSplitAcceptsDualOutputPayment(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "oracle:premium", &envelope.Monetization{
		Model:                 envelope.MonetizationSplit,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             50,
	})

	srv.paymentGate = testGateWithAppPayments(t, 10, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	ch := getChallenge(t, srv, "GET", "/data?topic=oracle:premium")

	// Build proof with TWO outputs: one to node, one to app
	proofB64 := buildMultiPayeeProof(t, ch, ch.Payees)

	req := httptest.NewRequest("GET", "/data?topic=oracle:premium", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid split payment, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("split payment accepted — both node and app paid directly")
}

func TestSplitRejectsMissingAppOutput(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "oracle:premium", &envelope.Monetization{
		Model:                 envelope.MonetizationSplit,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             50,
	})

	srv.paymentGate = testGateWithAppPayments(t, 10, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	ch := getChallenge(t, srv, "GET", "/data?topic=oracle:premium")

	// Build proof that only pays the node (missing app output)
	proofB64 := buildProof(t, ch, 10, testPayeeScript(t))

	req := httptest.NewRequest("GET", "/data?topic=oracle:premium", nil)
	req.Host = "localhost"
	req.Header.Set(HeaderX402Proof, proofB64)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 when app payee missing, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("correctly rejected split payment missing app output")
}

// --- Free-Infrastructure Node + App Monetization ---

func TestFreeNodeEnforcesAppPassthrough(t *testing.T) {
	srv := testServer(t)
	seedEnvelope(t, srv.envelopeStore, "oracle:free-infra", &envelope.Monetization{
		Model:                 envelope.MonetizationPassthrough,
		PayeeLockingScriptHex: appPayeeScript(),
		PriceSats:             75,
	})

	// Node price = 0 but app monetization enabled
	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:        0, // node is free
		NonceProvider:    &DevNonceProvider{},
		Resolver:         resolver,
		AllowPassthrough: true,
		AllowSplit:       true,
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	if srv.paymentGate == nil {
		t.Fatal("gate should exist even with node price=0 when app monetization is enabled")
	}

	// Non-monetized topic should pass through free
	req := httptest.NewRequest("GET", "/data?topic=unmonetized", nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unmonetized topic on free node, got %d", w.Code)
	}

	// Monetized topic should require payment (402)
	ch := getChallenge(t, srv, "GET", "/data?topic=oracle:free-infra")
	if ch.AmountSats != 75 {
		t.Fatalf("expected app price 75, got %d", ch.AmountSats)
	}
	if ch.PayeeLockingScriptHex != appPayeeScript() {
		t.Fatalf("expected app payee script, got %s", ch.PayeeLockingScriptHex)
	}

	t.Log("free node correctly enforces app-declared payment for monetized topics")
}

// --- Token Gating (Model 4) Tests ---

func TestTokenGatedTopicRequiresCredential(t *testing.T) {
	srv := testServer(t)

	// Generate a known keypair for the app
	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())

	seedEnvelope(t, srv.envelopeStore, "premium:data", &envelope.Monetization{
		Model:      envelope.MonetizationToken,
		AuthPubkey: appPubHex,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	// Request without token → 401
	req := httptest.NewRequest("GET", "/data?topic=premium:data", nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenGatedTopicAcceptsValidCredential(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())

	seedEnvelope(t, srv.envelopeStore, "premium:data", &envelope.Monetization{
		Model:      envelope.MonetizationToken,
		AuthPubkey: appPubHex,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
	srv.mux = http.NewServeMux()
	srv.routes()

	// Build a valid token: sign(sha256(topic:timestamp), appKey)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	message := "premium:data:" + ts
	digest := sha256.Sum256([]byte(message))
	sig, _ := appKey.Sign(digest[:])
	token := hex.EncodeToString(sig.Serialize()) + ":" + ts

	req := httptest.NewRequest("GET", "/data?topic=premium:data", nil)
	req.Host = "localhost"
	req.Header.Set("X-App-Token", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("token-gated access granted with valid credential — no payment involved")
}

func TestTokenGatedTopicRejectsWrongKey(t *testing.T) {
	srv := testServer(t)

	appKey, _ := ec.NewPrivateKey()
	appPubHex := hex.EncodeToString(appKey.PubKey().Compressed())

	seedEnvelope(t, srv.envelopeStore, "premium:data", &envelope.Monetization{
		Model:      envelope.MonetizationToken,
		AuthPubkey: appPubHex,
	})

	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.tokenGate = NewTokenGate(resolver, true)
	srv.mux = http.NewServeMux()
	srv.routes()

	// Sign with a DIFFERENT key
	wrongKey, _ := ec.NewPrivateKey()
	ts := fmt.Sprintf("%d", time.Now().Unix())
	message := "premium:data:" + ts
	digest := sha256.Sum256([]byte(message))
	sig, _ := wrongKey.Sign(digest[:])
	token := hex.EncodeToString(sig.Serialize()) + ":" + ts

	req := httptest.NewRequest("GET", "/data?topic=premium:data", nil)
	req.Host = "localhost"
	req.Header.Set("X-App-Token", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with wrong key, got %d: %s", w.Code, w.Body.String())
	}
	t.Log("correctly rejected token signed by wrong key")
}

// --- Paid POST /data (Ingestion Gating) ---

func TestPaidPostDataRoundTrip(t *testing.T) {
	srv := testServer(t)

	// Set up payment gate with passthrough enabled (so gate exists even at price 0)
	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats:        10,
		PayeeScriptHex:   testPayeeScript(t),
		NonceProvider:    &DevNonceProvider{},
		Resolver:         resolver,
		AllowPassthrough: true,
		AllowSplit:       true,
	})
	srv.mux = http.NewServeMux()
	srv.routes()

	// Build a valid signed envelope
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:paid-ingest",
		Payload:   `{"value":"paid-data"}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)
	envJSON, _ := json.Marshal(env)

	// Step 1: POST /data without auth or payment → should get 402
	req1 := httptest.NewRequest("POST", "/data", bytes.NewReader(envJSON))
	req1.Host = "localhost"
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w1, req1)
	if w1.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 without payment, got %d: %s", w1.Code, w1.Body.String())
	}

	// Extract challenge from the 402 response
	var ch X402Challenge
	json.NewDecoder(w1.Body).Decode(&ch)
	if ch.AmountSats != 10 {
		t.Fatalf("expected price 10, got %d", ch.AmountSats)
	}

	// Step 2: Build payment proof
	proofB64 := buildProof(t, &ch, 10, testPayeeScript(t))

	// Step 3: POST /data with payment proof — body must survive through
	// the payment gate (which reads it for hashing) to the handler
	req2 := httptest.NewRequest("POST", "/data", bytes.NewReader(envJSON))
	req2.Host = "localhost"
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set(HeaderX402Proof, proofB64)
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 for paid POST /data, got %d: %s", w2.Code, w2.Body.String())
	}

	// Verify the envelope was actually ingested
	var result map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&result)
	if result["accepted"] != true {
		t.Fatalf("expected accepted=true, got %v", result)
	}
	if result["topic"] != "test:paid-ingest" {
		t.Fatalf("expected topic=test:paid-ingest, got %v", result["topic"])
	}

	t.Log("paid POST /data round-trip: 402 → payment → accepted (body survived x402 verify)")
}

// suppress unused imports
var _ = script.Script{}
var _ = chainhash.Hash{}
var _ = transaction.NewTransaction
