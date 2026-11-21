package main

import (
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
)

func TestConfiguredRoutePrice(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{"node price", config.Config{API: config.APIConfig{PaymentSatoshis: 1}}, true},
		{"endpoint price", config.Config{API: config.APIConfig{EndpointPrices: map[string]int{"/data": 1}}}, true},
		{"no price", config.Config{}, false},
	}
	for _, tc := range cases {
		if got := hasConfiguredRoutePrice(&tc.cfg); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDiscoveryHasPricedRoute(t *testing.T) {
	cases := []struct {
		name      string
		discovery map[string]interface{}
		want      bool
	}{
		{"priced with no scheme", map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(0)}}}, false},
		{"priced with a scheme", map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(1)}}}, true},
		{"nothing priced", map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(0)}}}, false},
	}
	for _, tc := range cases {
		if got := discoveryHasPricedRoute(tc.discovery); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDoctorPaymentPathCheckNoARCNoUsableProof(t *testing.T) {
	for _, apiCfg := range []config.APIConfig{
		{PaymentSatoshis: 1},
		{PaymentSatoshis: 1, X402ProofScheme: true, RequireMempool: true},
	} {
		cfg := config.Config{API: apiCfg}
		out := captureStdout(t, func() {
			if got := doctorPaymentPathCheckWithDiscovery(&cfg, pricedDiscovery()); got != 1 {
				t.Fatalf("got %d issues, want 1", got)
			}
		})
		if !strings.Contains(out, "clients can't pay") || !strings.Contains(out, "BRC-121") ||
			!strings.Contains(out, "X-Bsv-Payment") || !strings.Contains(out, "enable [arc]") {
			t.Fatalf("unexpected output: %q", out)
		}
	}
}

func TestDoctorPaymentPathCheckNoARCDeprecatedProofOnly(t *testing.T) {
	cfg := config.Config{API: config.APIConfig{PaymentSatoshis: 1, X402ProofScheme: true}}
	out := captureStdout(t, func() {
		if got := doctorPaymentPathCheckWithDiscovery(&cfg, pricedDiscovery()); got != 1 {
			t.Fatalf("got %d issues, want 1", got)
		}
	})
	if !strings.Contains(out, "only the deprecated X402-Proof scheme") || !strings.Contains(out, "BRC-121") ||
		!strings.Contains(out, "X-Bsv-Payment") || !strings.Contains(out, "enable [arc]") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestDoctorPaymentPathCheckARCEnabledPriceMissingFromDiscovery(t *testing.T) {
	cfg := config.Config{ARC: config.ARCConfig{Enabled: true}, API: config.APIConfig{PaymentSatoshis: 1}}
	out := captureStdout(t, func() {
		if got := doctorPaymentPathCheckWithDiscovery(&cfg, unpricedDiscovery()); got != 1 {
			t.Fatalf("got %d issues, want 1", got)
		}
	})
	if !strings.Contains(out, "no available payment path") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestDoctorPaymentPathCheckARCEnabledPricePublished(t *testing.T) {
	cfg := config.Config{ARC: config.ARCConfig{Enabled: true}, API: config.APIConfig{PaymentSatoshis: 1}}
	out := captureStdout(t, func() {
		if got := doctorPaymentPathCheckWithDiscovery(&cfg, pricedDiscovery()); got != 0 {
			t.Fatalf("got %d issues, want 0", got)
		}
	})
	if !strings.Contains(out, "published in x402 discovery") || !strings.Contains(out, "ARC is enabled") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestDoctorPaymentPathCheckNothingPricedNoOutput(t *testing.T) {
	out := captureStdout(t, func() {
		if got := doctorPaymentPathCheckWithDiscovery(&config.Config{}, unpricedDiscovery()); got != 0 {
			t.Fatalf("got %d issues, want 0", got)
		}
	})
	if out != "" {
		t.Fatalf("got output %q, want none", out)
	}
}

func pricedDiscovery() map[string]interface{} {
	return map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(1)}}}
}

func unpricedDiscovery() map[string]interface{} {
	return map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(0)}}}
}
