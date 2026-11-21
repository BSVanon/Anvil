package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestPaymentDiscoveryPricesIgnoreProofSwitch(t *testing.T) {
	readEndpoints := func(off bool, endpoint string) []interface{} {
		t.Helper()
		srv := testServer(t)
		cfg := PaymentGateConfig{
			PriceSats: 61, PayeeScriptHex: testPayeeScript(t), NoProofScheme: off,
			EndpointPrices: map[string]int{"/status": 7, "/data": 11, "/broadcast": 19},
		}
		if !off {
			cfg.NonceProvider = &DevNonceProvider{}
		}
		srv.paymentGate = NewPaymentGate(cfg)
		rebuildRoutes(srv)
		w := getWithHeaders(srv, endpoint, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", endpoint, w.Code, w.Body.String())
		}
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		endpoints, ok := body["endpoints"].([]interface{})
		if !ok {
			t.Fatalf("%s has no endpoints: %s", endpoint, w.Body.String())
		}
		return endpoints
	}

	for _, endpoint := range []string{"/.well-known/x402", "/.well-known/x402-info"} {
		on, off := readEndpoints(false, endpoint), readEndpoints(true, endpoint)
		if !reflect.DeepEqual(off, on) {
			t.Fatalf("%s prices changed with proof switch: on=%v off=%v", endpoint, on, off)
		}
	}
}
