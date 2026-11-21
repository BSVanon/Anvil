package api

import "testing"

func TestProofOffKeepsChargingAndAppPaymentGates(t *testing.T) {
	payee := testPayeeScript(t)
	for _, tc := range []struct {
		name string
		cfg  PaymentGateConfig
	}{
		{name: "charging node", cfg: PaymentGateConfig{PriceSats: 100, PayeeScriptHex: payee}},
		{name: "app passthrough", cfg: PaymentGateConfig{PayeeScriptHex: payee, AllowPassthrough: true}},
		{name: "app split", cfg: PaymentGateConfig{PayeeScriptHex: payee, AllowSplit: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			onConfig := tc.cfg
			onConfig.NonceProvider = &DevNonceProvider{}
			offConfig := tc.cfg
			offConfig.NoProofScheme = true
			onGate := NewPaymentGate(onConfig)
			offGate := NewPaymentGate(offConfig)
			if onGate == nil || offGate == nil {
				t.Fatalf("payment gate missing: on=%p off=%p", onGate, offGate)
			}
			if offGate.nonceProvider != nil || !offGate.noProofScheme {
				t.Fatalf("proof-off gate retained proof machinery: provider=%T off=%v", offGate.nonceProvider, offGate.noProofScheme)
			}
			if offGate.priceSats != onGate.priceSats || offGate.payeeScriptHex != onGate.payeeScriptHex ||
				offGate.allowPassthrough != onGate.allowPassthrough || offGate.allowSplit != onGate.allowSplit {
				t.Fatalf("switch changed gate config: on=%+v off=%+v", onGate, offGate)
			}
		})
	}
}
