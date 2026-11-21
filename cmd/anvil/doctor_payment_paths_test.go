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

func TestDoctorPaymentPathCheck(t *testing.T) {
	cases := []struct {
		name      string
		cfg       config.Config
		discovery map[string]interface{}
		issues    int
		warning   bool
	}{
		{"priced with no scheme", config.Config{API: config.APIConfig{PaymentSatoshis: 1}}, map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(0)}}}, 1, true},
		{"priced with a scheme", config.Config{API: config.APIConfig{PaymentSatoshis: 1}}, map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(1)}}}, 0, false},
		{"nothing priced", config.Config{}, map[string]interface{}{"endpoints": []interface{}{map[string]interface{}{"price": float64(0)}}}, 0, false},
	}
	for _, tc := range cases {
		out := captureStdout(t, func() {
			if got := doctorPaymentPathCheckWithDiscovery(&tc.cfg, tc.discovery); got != tc.issues {
				t.Errorf("%s: got %d issues, want %d", tc.name, got, tc.issues)
			}
		})
		if got := strings.Contains(out, "no available payment path"); got != tc.warning {
			t.Errorf("%s: warning=%v, want %v; output=%q", tc.name, got, tc.warning, out)
		}
	}
}
