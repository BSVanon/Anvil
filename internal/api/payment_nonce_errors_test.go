package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkauth "github.com/bsv-blockchain/go-sdk/auth"
)

// fakeReplayNonceProvider always fails with go-sdk's auth.ErrReplayedNonce,
// to test writeMintNonceError's classification without depending on any
// real NonceProvider actually reaching that error today.
type fakeReplayNonceProvider struct{}

func (*fakeReplayNonceProvider) MintNonce() (*NonceUTXO, error) {
	return nil, sdkauth.ErrReplayedNonce
}

// fakeOpaqueFailureNonceProvider always fails with an unclassified error, to
// confirm the generic-failure fallback is unchanged (still 500).
type fakeOpaqueFailureNonceProvider struct{}

func (*fakeOpaqueFailureNonceProvider) MintNonce() (*NonceUTXO, error) {
	return nil, errOpaqueMintFailure
}

var errOpaqueMintFailure = &opaqueMintFailure{}

type opaqueMintFailure struct{}

func (*opaqueMintFailure) Error() string { return "opaque wallet failure" }

// TestReplayedNonceMapsTo402NotServerError: go-sdk's auth.ErrReplayedNonce
// from MintNonce must answer 402 (BRC-121 S5 step 5: a replayed payment is
// the client's failure, answered with a fresh 402), never the generic 500 a
// NonceProvider's other failures get.
func TestReplayedNonceMapsTo402NotServerError(t *testing.T) {
	gate := NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &fakeReplayNonceProvider{},
		mintBudget:     newMintBudget(1000, 60, time.Now),
	})
	if gate == nil {
		t.Fatal("expected a payment gate")
	}
	srv := testServer(t)
	srv.paymentGate = gate
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/data?topic=x", nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("a replayed-nonce MintNonce error must map to 402, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOpaqueMintFailureStillMapsTo500: an unclassified MintNonce failure
// (anything but *mintBudgetError or auth.ErrReplayedNonce) keeps answering
// 500 — this is a genuine node-side failure, not a payment-protocol outcome.
func TestOpaqueMintFailureStillMapsTo500(t *testing.T) {
	gate := NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: testPayeeScript(t),
		NonceProvider:  &fakeOpaqueFailureNonceProvider{},
		mintBudget:     newMintBudget(1000, 60, time.Now),
	})
	if gate == nil {
		t.Fatal("expected a payment gate")
	}
	srv := testServer(t)
	srv.paymentGate = gate
	srv.mux = http.NewServeMux()
	srv.routes()

	req := httptest.NewRequest("GET", "/data?topic=x", nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("an unclassified mint failure should still answer 500, got %d: %s", w.Code, w.Body.String())
	}
}
