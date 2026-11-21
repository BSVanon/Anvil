package api

import (
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestProofOffValidProofOnlyOffersDirectPayment(t *testing.T) {
	payee := testPayeeScript(t)
	proofGate := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
	})
	challenge := gateChallenge(t, proofGate, "/status")
	proof := buildProof(t, challenge, 100, payee)

	var arcCalls atomic.Int64
	arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		arcCalls.Add(1)
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	provider := &countingProvider{}
	offGate := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: payee, NonceProvider: provider,
		NoProofScheme: true, ARCClient: arc,
	})

	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "proof", headers: map[string]string{HeaderX402Proof: proof}},
		{name: "proof and direct", headers: map[string]string{
			HeaderX402Proof:  proof,
			HeaderBSVPayment: signedEFPaying(t, paidOut{payee, 100}),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := servePaymentGate(offGate, http.MethodGet, "/status", tc.headers)
			offer := decodeDirectOffer(t, w)
			if offer.Code != codeProofPaymentUnavailable || offer.AmountSats != 100 ||
				offer.PayeeLockingScriptHex != payee || !reflect.DeepEqual(offer.Accepts, []string{HeaderBSVPayment}) {
				t.Fatalf("unexpected proof-unavailable offer: %+v", offer)
			}
			if w.Header().Get(HeaderX402Receipt) != "" || w.Header().Get(HeaderX402Challenge) != "" {
				t.Fatal("proof-off request was accepted or challenged")
			}
		})
	}
	if arcCalls.Load() != 0 {
		t.Fatalf("mixed proof/direct request reached ARC %d times", arcCalls.Load())
	}
	assertNoChallengeActivity(t, offGate, provider)

	w := servePaymentGate(proofGate, http.MethodGet, "/status", map[string]string{HeaderX402Proof: proof})
	if w.Code != http.StatusOK || w.Header().Get(HeaderX402Receipt) == "" {
		t.Fatalf("control proof was not valid with proof scheme on: %d %s", w.Code, w.Body.String())
	}
}
