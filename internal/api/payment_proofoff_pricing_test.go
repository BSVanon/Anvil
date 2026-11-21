package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func directOfferOutputs(offer directPaymentOffer) []paidOut {
	if len(offer.Payees) == 0 {
		return []paidOut{{script: offer.PayeeLockingScriptHex, sats: uint64(offer.AmountSats)}}
	}
	outs := make([]paidOut, 0, len(offer.Payees))
	for _, payee := range offer.Payees {
		outs = append(outs, paidOut{script: payee.LockingScriptHex, sats: uint64(payee.AmountSats)})
	}
	return outs
}

func servePaymentGate(pg *PaymentGate, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "localhost"
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	pg.Middleware(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })(w, req)
	return w
}

func TestProofOffOffersMatchProofPricingAndPayDirectly(t *testing.T) {
	srv := testServer(t)
	node, app := testPayeeScript(t), appPayeeScript()
	key := mustKey(t)
	models := map[string]*envelope.Monetization{
		"passthrough": {Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: app, PriceSats: 70},
		"split":       {Model: envelope.MonetizationSplit, PayeeLockingScriptHex: app, PriceSats: 70},
		"token":       tokenModel(key),
		"disabled":    {Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: app, PriceSats: 70},
	}
	for topic, model := range models {
		seedEnvelopeAt(t, srv.envelopeStore, topic, `{"priced":true}`, time.Now().Unix(), model)
	}
	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})

	tests := []struct {
		name, target string
		configure    func(*PaymentGateConfig)
		noOffer      bool
	}{
		{name: "node only", target: "/status"},
		{name: "app passthrough", target: "/data?topic=passthrough", configure: func(cfg *PaymentGateConfig) { cfg.AllowPassthrough = true }},
		{name: "split", target: "/data?topic=split", configure: func(cfg *PaymentGateConfig) { cfg.AllowSplit = true }},
		{name: "token gated", target: "/data?topic=token"},
		{name: "disabled fallback", target: "/data?topic=disabled", noOffer: true},
		{name: "endpoint override", target: "/status", configure: func(cfg *PaymentGateConfig) {
			cfg.EndpointPrices = map[string]int{"/status": 275}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			makeConfig := func(off bool) PaymentGateConfig {
				cfg := PaymentGateConfig{
					PriceSats: 100, PayeeScriptHex: node, Resolver: resolver,
					NoProofScheme: off, ARCClient: arc,
				}
				if !off {
					cfg.NonceProvider = &DevNonceProvider{}
				}
				if tc.configure != nil {
					tc.configure(&cfg)
				}
				return cfg
			}
			offGate := NewPaymentGate(makeConfig(true))
			onGate := NewPaymentGate(makeConfig(false))
			offResponse := servePaymentGate(offGate, http.MethodGet, tc.target, nil)
			onResponse := servePaymentGate(onGate, http.MethodGet, tc.target, nil)

			if tc.noOffer {
				if offResponse.Code != http.StatusOK || onResponse.Code != http.StatusOK {
					t.Fatalf("disabled fallback differed: off=%d on=%d", offResponse.Code, onResponse.Code)
				}
				return
			}

			offer := decodeDirectOffer(t, offResponse)
			var challenge X402Challenge
			if onResponse.Code != http.StatusPaymentRequired || json.Unmarshal(onResponse.Body.Bytes(), &challenge) != nil {
				t.Fatalf("decode proof-on challenge: %d %s", onResponse.Code, onResponse.Body.String())
			}
			if offer.AmountSats != challenge.AmountSats || offer.PayeeLockingScriptHex != challenge.PayeeLockingScriptHex ||
				!reflect.DeepEqual(offer.Payees, challenge.Payees) {
				t.Fatalf("proof-off offer differs from proof-on pricing: offer=%+v challenge=%+v", offer, challenge)
			}

			outputs := directOfferOutputs(offer)
			payment := signedEFPaying(t, outputs...)
			paid := servePaymentGate(offGate, http.MethodGet, tc.target, map[string]string{HeaderBSVPayment: payment})
			if paid.Code != http.StatusOK || paid.Header().Get(HeaderX402Receipt) == "" {
				t.Fatalf("payment built from offer was refused: %d %s", paid.Code, paid.Body.String())
			}

			for underpaid := range outputs {
				short := append([]paidOut(nil), outputs...)
				short[underpaid].sats--
				w := servePaymentGate(offGate, http.MethodGet, tc.target, map[string]string{
					HeaderBSVPayment: signedEFPaying(t, short...),
				})
				if w.Code != http.StatusPaymentRequired {
					t.Fatalf("underpaid payee %d was not refused: %d %s", underpaid, w.Code, w.Body.String())
				}
			}
		})
	}
}
