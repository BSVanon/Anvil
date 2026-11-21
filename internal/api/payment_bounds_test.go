package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// paddedPayment pays 200 sats to payeeScriptHex and carries pad bytes in an
// OP_FALSE OP_RETURN output. It spends nonce when nonce is not nil.
func paddedPayment(t *testing.T, nonce *NonceUTXO, payeeScriptHex string, pad int) *transaction.Transaction {
	t.Helper()
	src, vout := chainhash.DoubleHashH([]byte("padded payment")), uint32(0)
	if nonce != nil {
		h, err := chainhash.NewHashFromHex(nonce.TxID)
		if err != nil {
			t.Fatalf("nonce txid: %v", err)
		}
		src, vout = *h, uint32(nonce.Vout)
	}
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &src, SourceTxOutIndex: vout, SequenceNumber: 0xffffffff})
	payee, err := bsvscript.NewFromHex(payeeScriptHex)
	if err != nil {
		t.Fatalf("payee script: %v", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 200, LockingScript: payee})
	data := &bsvscript.Script{bsvscript.OpFALSE, bsvscript.OpRETURN}
	_ = data.AppendPushData(make([]byte, pad))
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: data})
	return tx
}

// paddedSignedDirectPayment is paddedPayment's X-Bsv-Payment counterpart: a
// genuinely signed P2PKH spend (embedded source output + real signature,
// same shape as buildSignedDirectPaymentTx, payment_direct_verify_test.go)
// paying 200 sats to payeeScriptHex, padded with pad bytes in an OP_FALSE
// OP_RETURN output for header-size-cap testing. verifyDirectPaymentInputs
// verifies every input's signature unconditionally, so a direct-payment
// test fixture — unlike paddedPayment's nonce-bound fixture, which the
// proof flow's dev-mode nonce sentinel exempts from that check — needs one.
// Returned pre-serialized as extended-format hex (EFHex requires the
// embedded source output tx.Bytes() alone would drop).
func paddedSignedDirectPayment(t *testing.T, payeeScriptHex string, pad int) string {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr, err := bsvscript.NewAddressFromPublicKey(key.PubKey(), true)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		t.Fatalf("build lock script: %v", err)
	}
	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: lockScript})
	sourceTxID := sourceTx.TxID()

	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:        sourceTxID,
		SourceTxOutIndex:  0,
		SequenceNumber:    0xffffffff,
		SourceTransaction: sourceTx,
	})
	payee, err := bsvscript.NewFromHex(payeeScriptHex)
	if err != nil {
		t.Fatalf("payee script: %v", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 200, LockingScript: payee})
	data := &bsvscript.Script{bsvscript.OpFALSE, bsvscript.OpRETURN}
	_ = data.AppendPushData(make([]byte, pad))
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: data})

	unlock, err := p2pkh.Unlock(key, nil)
	if err != nil {
		t.Fatalf("create unlock template: %v", err)
	}
	tx.Inputs[0].UnlockingScriptTemplate = unlock
	if err := tx.Sign(); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	efHex, err := tx.EFHex()
	if err != nil {
		t.Fatalf("serialize extended format: %v", err)
	}
	return efHex
}

// serveGateMeasured is serveGate that also reports the bytes allocated while
// the request was served.
func serveGateMeasured(pg *PaymentGate, header, value string) (*httptest.ResponseRecorder, uint64) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	w := serveGate(pg, http.MethodGet, "/status", header, value)
	runtime.ReadMemStats(&after)
	return w, after.TotalAlloc - before.TotalAlloc
}

// A payment header over maxPaymentHeaderBytes is refused with 431 before it
// is decoded, even when its content would pay; one at the cap is decoded.
func TestPaymentHeaderSizeCap(t *testing.T) {
	pg := testGate(t, 100)
	pg.arcClient = mockARCServer(t) // direct payments need ARC
	payee := testPayeeScript(t)
	proof := func(pad int) string {
		ch := gateChallenge(t, pg, "/status")
		return proofForTx(t, ch, paddedPayment(t, ch.NonceUTXO, payee, pad))
	}
	direct := func(pad int) string { return paddedSignedDirectPayment(t, payee, pad) }
	atCap := strings.Repeat("ab", maxPaymentHeaderBytes/2)
	cases := []struct {
		name, header, value string
		wantCode            int
	}{
		{"proof under the cap pays", HeaderX402Proof, proof(128 << 10), http.StatusOK},
		{"proof over the cap", HeaderX402Proof, proof(160 << 10), http.StatusRequestHeaderFieldsTooLarge},
		{"direct payment under the cap pays", HeaderBSVPayment, direct(120 << 10), http.StatusOK},
		{"direct payment over the cap", HeaderBSVPayment, direct(140 << 10), http.StatusRequestHeaderFieldsTooLarge},
		{"direct payment at the cap is decoded", HeaderBSVPayment, atCap, http.StatusPaymentRequired},
		{"direct payment one byte over the cap", HeaderBSVPayment, atCap + "a", http.StatusRequestHeaderFieldsTooLarge},
	}
	for _, tc := range cases {
		w, alloc := serveGateMeasured(pg, tc.header, tc.value)
		if w.Code != tc.wantCode {
			t.Fatalf("%s (%d bytes): got %d %s, want %d", tc.name, len(tc.value), w.Code, w.Body.String(), tc.wantCode)
		}
		if tc.wantCode == http.StatusRequestHeaderFieldsTooLarge && alloc > 64<<10 {
			t.Fatalf("%s: refusing a %d-byte header allocated %d bytes, want under 64 KiB (no decode)", tc.name, len(tc.value), alloc)
		}
		t.Logf("%s: %d-byte header, status %d, %d bytes allocated", tc.name, len(tc.value), w.Code, alloc)
	}
}

// A challenge verifies at most maxProofAttempts proofs; after that, even a
// proof that pays is refused.
func TestX402ProofAttemptsSpendChallenge(t *testing.T) {
	pg := testGate(t, 100)
	ch := gateChallenge(t, pg, "/status")
	wrongPayee := buildProof(t, ch, 200, "76a914000000000000000000000000000000000000000088ac")
	for i := 1; i <= maxProofAttempts; i++ {
		if w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, wrongPayee); w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "no distinct output pays") {
			t.Fatalf("failed proof %d: got %d %s", i, w.Code, w.Body.String())
		}
	}
	good := buildProof(t, ch, 200, testPayeeScript(t))
	if w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, good); w.Code != http.StatusPaymentRequired {
		t.Fatalf("paying proof after %d failures: got %d %s, want 402", maxProofAttempts, w.Code, w.Body.String())
	}
	pg.mu.Lock()
	pending := len(pg.pendingChallenges)
	pg.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d challenges still pending, want the spent one removed", pending)
	}
}

// An ambiguous ARC failure answers 503 without consuming a proof attempt or
// offering a replacement payment. The same proof remains retryable.
func TestX402RetryAfterTransientARCFailure(t *testing.T) {
	var calls atomic.Int32
	arc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= maxProofAttempts+1 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(txrelay.ARCResponse{TxID: submittedTxID(t, r), Status: "SEEN_ON_NETWORK"})
	}))
	t.Cleanup(arc.Close)
	payee := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
		RequireMempool: true, ARCClient: txrelay.NewARCClient(arc.URL, "")})
	ch := gateChallenge(t, pg, "/status")
	proof := buildProof(t, ch, 200, payee)
	for i := 1; i <= maxProofAttempts+1; i++ {
		w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, proof)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "ARC broadcast failed") {
			t.Fatalf("try %d: got %d %s, want 503 from ambiguous ARC failure", i, w.Code, w.Body.String())
		}
		if w.Header().Get(HeaderX402Challenge) != "" || w.Header().Get(headerBRC121Sats) != "" {
			t.Fatalf("try %d advertised a new payment after an ambiguous submit", i)
		}
	}
	pg.mu.Lock()
	pending := len(pg.pendingChallenges)
	pg.mu.Unlock()
	if pending != 1 {
		t.Fatalf("ambiguous failures consumed the challenge; %d pending, want 1", pending)
	}
	if w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, proof); w.Code != http.StatusOK {
		t.Fatalf("same proof after ambiguous failures: got %d %s, want 200", w.Code, w.Body.String())
	}
}

// Proofs refused by the request binding do not count, so a caller who sends
// a challenge's proof with a different request cannot use up its attempts.
func TestX402UnboundProofsDoNotCountAgainstChallenge(t *testing.T) {
	pg := testGate(t, 100)
	ch := gateChallenge(t, pg, "/status")
	good := buildProof(t, ch, 200, testPayeeScript(t))
	next := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		req.Host = "localhost"
		req.Header.Set("Accept", "text/xml")
		req.Header.Set(HeaderX402Proof, good)
		w := httptest.NewRecorder()
		pg.Middleware(next)(w, req)
		if w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "does not match live request") {
			t.Fatalf("unbound proof %d: got %d %s", i, w.Code, w.Body.String())
		}
	}
	if w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, good); w.Code != http.StatusOK {
		t.Fatalf("bound proof after 10 unbound ones: got %d %s, want 200", w.Code, w.Body.String())
	}
}

// Concurrent proofs for one challenge are counted when they start, so only
// maxProofAttempts of them reach the expensive steps. Of those, the one that
// claims the transaction first waits on a blocked ARC; the others carry the
// same transaction while it is in flight, so they are refused as replays
// (payment_replay.go), and the last of them removes the spent challenge.
// Every sender past the count is refused, as spent or as unknown.
func TestX402ConcurrentProofsCappedPerChallenge(t *testing.T) {
	release := make(chan struct{})
	var arcCalls atomic.Int32
	arc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arcCalls.Add(1)
		<-release
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(arc.Close)
	var once sync.Once
	releaseARC := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseARC)
	payee := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
		RequireMempool: true, ARCClient: txrelay.NewARCClient(arc.URL, "")})
	ch := gateChallenge(t, pg, "/status")
	proof := buildProof(t, ch, 200, payee)

	const senders = 10
	results := make(chan *httptest.ResponseRecorder, senders)
	for i := 0; i < senders; i++ {
		go func() { results <- serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, proof) }()
	}
	deadline := time.After(10 * time.Second)
	spent, inFlight := 0, 0
	for spent+inFlight < senders-1 {
		select {
		case w := <-results:
			switch {
			case w.Code == http.StatusPaymentRequired && (strings.Contains(w.Body.String(), "challenge spent") ||
				strings.Contains(w.Body.String(), "unknown or expired challenge")):
				spent++
			case w.Code == http.StatusPaymentRequired && strings.Contains(w.Body.String(), codePaymentReplayed):
				inFlight++
			default:
				t.Fatalf("a sender refused while one proof waits on ARC: got %d %s", w.Code, w.Body.String())
			}
		case <-deadline:
			t.Fatalf("%d senders refused as spent and %d as in flight after 10s; %d proofs reached ARC", spent, inFlight, arcCalls.Load())
		}
	}
	if spent != senders-maxProofAttempts || inFlight != maxProofAttempts-1 {
		t.Fatalf("got %d refused as spent and %d as in flight, want %d and %d", spent, inFlight, senders-maxProofAttempts, maxProofAttempts-1)
	}
	releaseARC()
	if w := <-results; w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), codePaymentSubmitUncertain) {
		t.Fatalf("the proof that claimed the transaction: got %d %s, want uncertain-submit 503", w.Code, w.Body.String())
	} else if w.Header().Get(HeaderX402Challenge) != "" || w.Header().Get(headerBRC121Sats) != "" {
		t.Fatal("ambiguous ARC failure advertised another payment")
	}
	if n := arcCalls.Load(); n != 1 {
		t.Fatalf("%d proofs reached ARC, want 1", n)
	}
}

// Reachability on a node configured like the live ones: no node price and
// the default app payment models on (internal/config/config.go). An
// unauthenticated caller publishes a topic that declares a price, and its
// payment headers then reach the transaction parse and the nonce script
// check.
func TestX402ReachableOnFreeNodeThroughPublishedTopic(t *testing.T) {
	srv := testServer(t)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		NonceProvider:    &keyNonceProvider{key: mustKey(t)},
		Resolver:         NewTopicMonetizationResolver(srv.envelopeStore),
		AllowPassthrough: true,
		AllowSplit:       true,
		MaxAppPriceSats:  10000,
		ARCClient:        mockARCServer(t), // direct payments need ARC
	})
	srv.mux = http.NewServeMux()
	srv.routes()
	send := func(method, target, header, value string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Host = "localhost"
		if header != "" {
			req.Header.Set(header, value)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	env := &envelope.Envelope{Type: "data", Topic: "probe:priced", Payload: `{"probe":true}`, Durable: true, Timestamp: time.Now().Unix(),
		Monetization: &envelope.Monetization{Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 1}}
	env.Sign(mustKey(t))
	body, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if w := send(http.MethodPost, "/data", "", "", body); w.Code != http.StatusOK {
		t.Fatalf("unauthenticated POST /data: got %d %s", w.Code, w.Body.String())
	}

	const target = "/data?topic=probe:priced"
	if w := send(http.MethodGet, target, HeaderBSVPayment, "00", nil); w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "invalid transaction in payment header") {
		t.Fatalf("X-Bsv-Payment: got %d %s, want 402 from the transaction parse", w.Code, w.Body.String())
	}
	ch := getChallenge(t, srv, http.MethodGet, target)
	proof := proofForTx(t, ch, nonceSpend(t, ch.NonceUTXO, nil, 1, 1, appPayeeScript(), fourKBBomb()))
	if w := send(http.MethodGet, target, HeaderX402Proof, proof, nil); w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "nonce input signature invalid") {
		t.Fatalf("X402-Proof: got %d %s, want 402 from the nonce script check", w.Code, w.Body.String())
	}
}
