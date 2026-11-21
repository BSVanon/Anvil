package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkauth "github.com/bsv-blockchain/go-sdk/auth"
)

// fakeReplayNonceProvider always fails with go-sdk's auth.ErrReplayedNonce,
// to pin how writeMintNonceError answers that error if a NonceProvider ever
// returns it.
type fakeReplayNonceProvider struct{}

func (*fakeReplayNonceProvider) MintNonce(context.Context) (*NonceUTXO, error) {
	return nil, sdkauth.ErrReplayedNonce
}

// fakeOpaqueFailureNonceProvider always fails with an unclassified error, to
// confirm the generic-failure fallback is unchanged (still 500).
type fakeOpaqueFailureNonceProvider struct{}

func (*fakeOpaqueFailureNonceProvider) MintNonce(context.Context) (*NonceUTXO, error) {
	return nil, errOpaqueMintFailure
}

var errOpaqueMintFailure = &opaqueMintFailure{}

type opaqueMintFailure struct{}

func (*opaqueMintFailure) Error() string { return "opaque wallet failure" }

// TestReplayedNonceMintFailureStaysServerError: go-sdk's auth.ErrReplayedNonce
// from MintNonce answers 500, like any other mint failure. A mint runs while the
// node issues a challenge, before any payment exists, so the failure is the
// node's own, never a payment refusal (402).
func TestReplayedNonceMintFailureStaysServerError(t *testing.T) {
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

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a replayed-nonce MintNonce error is a node failure and must answer 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOpaqueMintFailureStillMapsTo500: a MintNonce failure other than
// *mintBudgetError keeps answering 500. It is a node-side failure, not a
// payment-protocol outcome.
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
