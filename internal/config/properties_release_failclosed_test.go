package config

import (
	"strings"
	"testing"
)

func TestChangedConfigurationSectionsRejectInvalidValues(t *testing.T) {
	tests := []struct {
		key  string
		body string
	}{
		{"certgate.revocation_check", "[certgate]\nrevocation_check = \"sometimes\"\n"},
		{"gateway.txt_cache_ttl", "[gateway]\ntxt_cache_ttl = -1\n"},
		{"content.max_tracked_origins", "[content]\nmax_tracked_origins = -1\n"},
		{"messaging.forward_copy_ttl", "[messaging]\nforward_copy_ttl = -1\n"},
		{"api.payment_satoshis", "[api]\npayment_satoshis = -1\n"},
		{"api.endpoint_prices", "[api]\nendpoint_prices = { \"/data\" = -1 }\n"},
		{"api.x402_mint_burst", "[api]\nx402_mint_burst = -1\n"},
		{"api.x402_mints_per_minute", "[api]\nx402_mints_per_minute = -1\n"},
		{"api.nonce_pool_size", "[api]\nnonce_pool_size = -1\n"},
		{"api.app_payments.max_app_price_sats", "[api.app_payments]\nmax_app_price_sats = -1\n"},
		{"mesh.allowed_peers", "[mesh]\nallowed_peers = [\"not-a-key\"]\n"},
		{"overlay.named_peers", "[overlay]\nnamed_peers = [\"not-a-url\"]\n"},
	}
	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			_, err := Load(writeTestConfig(t, t.TempDir(), test.body))
			if err == nil {
				t.Fatal("invalid value loaded")
			}
			if !strings.Contains(err.Error(), test.key) {
				t.Fatalf("error %q does not name %s", err, test.key)
			}
		})
	}
}
