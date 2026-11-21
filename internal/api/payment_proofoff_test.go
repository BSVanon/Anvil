package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func decodeDirectOffer(t *testing.T, w *httptest.ResponseRecorder) directPaymentOffer {
	t.Helper()
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("got %d %s, want 402", w.Code, w.Body.String())
	}
	var offer directPaymentOffer
	if err := json.Unmarshal(w.Body.Bytes(), &offer); err != nil {
		t.Fatalf("decode payment offer: %v", err)
	}
	return offer
}

func TestProofOffSplitOffersDirectPaymentWithoutChallengeState(t *testing.T) {
	srv := testServer(t)
	node, app := testPayeeScript(t), appPayeeScript()
	seedEnvelopeAt(t, srv.envelopeStore, "split", `{"priced":true}`, time.Now().Unix(), &envelope.Monetization{
		Model: envelope.MonetizationSplit, PayeeLockingScriptHex: app, PriceSats: 50,
	})
	provider := &countingProvider{}
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: node, NonceProvider: provider, NoProofScheme: true,
		Resolver: NewTopicMonetizationResolver(srv.envelopeStore), AllowSplit: true,
	})
	w := serveGate(pg, http.MethodGet, "/data?topic=split", "", "")
	offer := decodeDirectOffer(t, w)
	if w.Header().Get(HeaderX402Challenge) != "" {
		t.Fatal("proof-off response set X402-Challenge")
	}
	if offer.AmountSats != 150 || offer.PayeeLockingScriptHex != node || len(offer.Payees) != 2 {
		t.Fatalf("unexpected split offer: %+v", offer)
	}
	if !reflect.DeepEqual(offer.Accepts, []string{HeaderBSVPayment}) || offer.Code != codePaymentRequired {
		t.Fatalf("unexpected direct payment metadata: %+v", offer)
	}
	pg.mu.Lock()
	pending, reserved := len(pg.pendingChallenges), pg.reservedPending
	pg.mu.Unlock()
	if provider.mints.Load() != 0 || pending != 0 || reserved != 0 {
		t.Fatalf("proof-off request minted or reserved challenge state: mints=%d pending=%d reserved=%d", provider.mints.Load(), pending, reserved)
	}
}

func TestProofOffBRC121OfferIsByteForByteLegacyResponse(t *testing.T) {
	newGate := func(off bool) *PaymentGate {
		pg := NewPaymentGate(PaymentGateConfig{
			PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}, NoProofScheme: off,
		})
		pg.brc121 = &brc121Gate{server: "server"}
		return pg
	}
	legacy := serveGate(newGate(false), http.MethodGet, "/status", "", "")
	off := serveGate(newGate(true), http.MethodGet, "/status", "", "")
	if off.Code != legacy.Code || !reflect.DeepEqual(off.Header(), legacy.Header()) || !reflect.DeepEqual(off.Body.Bytes(), legacy.Body.Bytes()) {
		t.Fatalf("proof-off BRC-121 response changed: legacy=%d %v %q off=%d %v %q",
			legacy.Code, legacy.Header(), legacy.Body.String(), off.Code, off.Header(), off.Body.String())
	}
}

func TestProofOffNodeOnlyWithoutBRC121OffersDirectPayment(t *testing.T) {
	provider := &countingProvider{}
	payee := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: payee, NonceProvider: provider, NoProofScheme: true,
	})
	w := serveGate(pg, http.MethodGet, "/status", "", "")
	offer := decodeDirectOffer(t, w)
	if offer.AmountSats != 100 || offer.PayeeLockingScriptHex != payee || len(offer.Payees) != 0 || offer.Code != codePaymentRequired {
		t.Fatalf("unexpected node offer: %+v", offer)
	}
	if provider.mints.Load() != 0 || w.Header().Get(HeaderX402Challenge) != "" {
		t.Fatal("node-only proof-off offer minted or advertised a challenge")
	}
}

func TestProofOffProofHeaderIsNeverVerified(t *testing.T) {
	provider := &countingProvider{}
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: provider, NoProofScheme: true,
	})
	w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, "not-base64")
	offer := decodeDirectOffer(t, w)
	if offer.Code != codeProofPaymentUnavailable || !strings.Contains(offer.Description, "proof payments aren't offered") {
		t.Fatalf("proof-off request reached proof rejection instead of unavailable offer: %+v", offer)
	}
	if provider.mints.Load() != 0 || len(pg.pendingChallenges) != 0 {
		t.Fatal("proof-off proof request touched challenge state")
	}
}

func TestProofOffNilProviderAcceptsSplitDirectPayment(t *testing.T) {
	srv := testServer(t)
	node, app := testPayeeScript(t), appPayeeScript()
	seedEnvelopeAt(t, srv.envelopeStore, "split-direct", `{"priced":true}`, time.Now().Unix(), &envelope.Monetization{
		Model: envelope.MonetizationSplit, PayeeLockingScriptHex: app, PriceSats: 50,
	})
	arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: node, NoProofScheme: true, ARCClient: arc,
		Resolver: NewTopicMonetizationResolver(srv.envelopeStore), AllowSplit: true,
	})
	if pg == nil {
		t.Fatal("proof-off gate with nil nonce provider was not built")
	}
	req := httptest.NewRequest(http.MethodGet, "/data?topic=split-direct", nil)
	req.Header.Set(HeaderBSVPayment, signedEFPaying(t, paidOut{node, 100}, paidOut{app, 50}))
	w := httptest.NewRecorder()
	served := false
	pg.Middleware(func(w http.ResponseWriter, r *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	})(w, req)
	if w.Code != http.StatusOK || !served {
		t.Fatalf("split direct payment was not accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestProofOffKeepsChallengeFootprintCapBeforeOffer(t *testing.T) {
	provider := &countingProvider{}
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: provider, NoProofScheme: true,
	})
	w := serveGate(pg, http.MethodGet, "/"+strings.Repeat("x", maxChallengeFootprint), "", "")
	if w.Code != http.StatusBadRequest || provider.mints.Load() != 0 || w.Header().Get(HeaderX402Challenge) != "" {
		t.Fatalf("footprint cap did not precede proof-off offer: %d %s", w.Code, w.Body.String())
	}
}

func TestPaymentMethodDiscoveryTracksProofSwitch(t *testing.T) {
	for _, tc := range []struct {
		name string
		off  bool
	}{
		{name: "off", off: true},
		{name: "on", off: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServer(t)
			srv.paymentGate = NewPaymentGate(PaymentGateConfig{
				PriceSats: 1, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{}, NoProofScheme: tc.off,
			})
			rebuildRoutes(srv)
			for _, endpoint := range []string{"/.well-known/x402", "/.well-known/x402-info", "/.well-known/anvil"} {
				w := getWithHeaders(srv, endpoint, nil)
				if w.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", endpoint, w.Code, w.Body.String())
				}
				var body map[string]interface{}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				var methods []interface{}
				if endpoint == "/.well-known/x402" {
					methods, _ = body["payment_methods"].([]interface{})
				} else {
					payment, _ := body["payment"].(map[string]interface{})
					methods, _ = payment["methods"].([]interface{})
				}
				joined := fmtMethods(methods)
				if !strings.Contains(joined, "BRC-121") || !strings.Contains(joined, HeaderBSVPayment) {
					t.Fatalf("%s: missing production methods: %v", endpoint, methods)
				}
				hasProof := strings.Contains(joined, "X402-Challenge/Proof (deprecated)")
				if hasProof == tc.off {
					t.Fatalf("%s: proof method mismatch for off=%v: %v", endpoint, tc.off, methods)
				}
			}
		})
	}
}

func fmtMethods(methods []interface{}) string {
	parts := make([]string, 0, len(methods))
	for _, method := range methods {
		parts = append(parts, method.(string))
	}
	return strings.Join(parts, ",")
}

type unreadPaymentBody struct{ reads int }

func (b *unreadPaymentBody) Read([]byte) (int, error) {
	b.reads++
	return 0, http.ErrBodyReadAfterClose
}

func (b *unreadPaymentBody) Close() error { return nil }

func TestProofOffUnpaidRequestDoesNotReadBody(t *testing.T) {
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NoProofScheme: true,
	})
	body := &unreadPaymentBody{}
	req := httptest.NewRequest(http.MethodPost, "/broadcast", body)
	w := httptest.NewRecorder()
	pg.Middleware(func(http.ResponseWriter, *http.Request) { t.Fatal("unpaid request was served") })(w, req)
	if w.Code != http.StatusPaymentRequired || body.reads != 0 {
		t.Fatalf("proof-off request read its body: status=%d reads=%d", w.Code, body.reads)
	}
}
