package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/txrelay"
)

// mockARCWithStatus returns an ARC client whose server answers every submit
// with txStatus status at blockHeight height.
func mockARCWithStatus(t *testing.T, status string, height uint32) *txrelay.ARCClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(txrelay.ARCResponse{TxID: submittedTxID(t, r), Status: status, BlockHeight: height})
	}))
	t.Cleanup(srv.Close)
	return txrelay.NewARCClient(srv.URL, "")
}

// refusedARCStatuses are the ARC statuses that do not show the network
// accepted a transaction (arcAccepted, payment_arc.go): every status before a
// node accepts it, the orphan status, and the failures.
var refusedARCStatuses = []string{
	"", "UNKNOWN", "QUEUED", "RECEIVED", "STORED",
	"ANNOUNCED_TO_NETWORK", "REQUESTED_BY_NETWORK", "SENT_TO_NETWORK", "ACCEPTED_BY_NETWORK",
	"SEEN_IN_ORPHAN_MEMPOOL", "DOUBLE_SPEND_ATTEMPTED", "REJECTED", "MINED_IN_STALE_BLOCK",
}

// A direct payment is accepted only when ARC reports SEEN_ON_NETWORK or MINED.
func TestDirectPaymentNeedsNetworkAcceptance(t *testing.T) {
	payee := testPayeeScript(t)
	payees := []Payee{{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100}}
	pay := func(status string) error {
		pg := NewPaymentGate(PaymentGateConfig{
			PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
			ARCClient: mockARCWithStatus(t, status, 0),
		})
		ef, err := buildSignedDirectPaymentTx(t, payee, 100).EFHex()
		if err != nil {
			t.Fatalf("serialize extended format: %v", err)
		}
		_, err = pg.verifyDirectPayment(context.Background(), ef, payees)
		return err
	}
	for _, status := range refusedARCStatuses {
		err := pay(status)
		var refusal *paymentRefusal
		if !errors.As(err, &refusal) || refusal.code != codePaymentNotAccepted {
			t.Fatalf("ARC status %q: want a %s refusal, got %v", status, codePaymentNotAccepted, err)
		}
	}
	if err := pay("SEEN_ON_NETWORK"); err != nil {
		t.Fatalf("ARC status SEEN_ON_NETWORK: want the payment accepted, got %v", err)
	}
}

// A challenge-bound proof whose challenge requires mempool acceptance takes
// SEEN_ON_NETWORK. MINED additionally needs a local-header merkle proof.
func TestProofPaymentNeedsNetworkAcceptance(t *testing.T) {
	pay := func(status string) *httptest.ResponseRecorder {
		srv := testServer(t)
		srv.paymentGate = NewPaymentGate(PaymentGateConfig{
			PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
			RequireMempool: true, ARCClient: mockARCWithStatus(t, status, 0),
		})
		srv.mux = http.NewServeMux()
		srv.routes()
		ch := getChallenge(t, srv, http.MethodGet, "/stats")
		if !ch.RequireMempoolAccept {
			t.Fatal("the challenge must require mempool acceptance")
		}
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		req.Host = "localhost"
		req.Header.Set(HeaderX402Proof, buildProof(t, ch, 100, testPayeeScript(t)))
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	for _, status := range refusedARCStatuses {
		requirePaymentCode(t, pay(status), codePaymentNotAccepted)
	}
	if w := pay("SEEN_ON_NETWORK"); w.Code != http.StatusOK {
		t.Fatalf("ARC status SEEN_ON_NETWORK: got %d %s, want 200", w.Code, w.Body.String())
	}
	if w := pay("MINED"); w.Code != http.StatusPaymentRequired {
		t.Fatalf("unproved ARC status MINED: got %d %s, want 402", w.Code, w.Body.String())
	}
}
