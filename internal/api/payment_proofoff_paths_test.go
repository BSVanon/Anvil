package api

import (
	"net/http"
	"testing"
	"time"
)

func TestPaymentPathsKeepBehaviorAcrossProofSwitch(t *testing.T) {
	arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	payee := testPayeeScript(t)
	directPayment := signedEFPaying(t, paidOut{payee, 100})
	capacityPayment := signedEFPaying(t, paidOut{payee, 100})

	for _, off := range []bool{false, true} {
		name := "on"
		if off {
			name = "off"
		}
		t.Run(name+"/direct and replay", func(t *testing.T) {
			cfg := PaymentGateConfig{
				PriceSats: 100, PayeeScriptHex: payee, NoProofScheme: off, ARCClient: arc,
			}
			if !off {
				cfg.NonceProvider = &DevNonceProvider{}
			}
			pg := NewPaymentGate(cfg)
			first := servePaymentGate(pg, http.MethodGet, "/status", map[string]string{HeaderBSVPayment: directPayment})
			if first.Code != http.StatusOK || first.Header().Get(HeaderX402Receipt) == "" {
				t.Fatalf("first direct payment: %d %s", first.Code, first.Body.String())
			}
			second := servePaymentGate(pg, http.MethodGet, "/status", map[string]string{HeaderBSVPayment: directPayment})
			if second.Code != http.StatusPaymentRequired || codeOf(t, second) != codePaymentReplayed {
				t.Fatalf("direct replay: %d %s", second.Code, second.Body.String())
			}
		})

		t.Run(name+"/full replay set", func(t *testing.T) {
			cfg := PaymentGateConfig{
				PriceSats: 100, PayeeScriptHex: payee, NoProofScheme: off, ARCClient: arc,
			}
			if !off {
				cfg.NonceProvider = &DevNonceProvider{}
			}
			pg := NewPaymentGate(cfg)
			pg.replays = newPaymentReplaySet(time.Hour, 1, time.Now)
			old := replayTxID(1)
			if !pg.replays.begin(old) {
				t.Fatal("could not fill replay set")
			}
			pg.replays.end(old, true)
			w := servePaymentGate(pg, http.MethodGet, "/status", map[string]string{HeaderBSVPayment: capacityPayment})
			if w.Code != http.StatusServiceUnavailable || codeOf(t, w) != codePaymentReplayFull {
				t.Fatalf("full replay set: %d %s", w.Code, w.Body.String())
			}
			if w.Header().Get(HeaderX402Challenge) != "" || w.Header().Get(headerBRC121Sats) != "" {
				t.Fatal("full replay set advertised another payment")
			}
		})

		t.Run(name+"/brc121 and replay", func(t *testing.T) {
			fixture := newBRC121Fix(t, 100)
			fixture.pg.noProofScheme = off
			headers := fixture.payment(t, 100, brc121Pay{})
			first := fixture.serve(brc121Path, "192.0.2.1:1", headers)
			if first.Code != http.StatusOK || first.Header().Get(HeaderX402Receipt) == "" {
				t.Fatalf("first BRC-121 payment: %d %s", first.Code, first.Body.String())
			}
			second := fixture.serve(brc121Path, "192.0.2.1:1", headers)
			if second.Code != http.StatusPaymentRequired || codeOf(t, second) != codeBRC121Replayed {
				t.Fatalf("BRC-121 replay: %d %s", second.Code, second.Body.String())
			}
		})
	}
}
