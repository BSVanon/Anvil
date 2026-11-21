package config

import (
	"fmt"
	"net/url"
	"strings"
)

// validateChangedSectionValues rejects explicit values that the release's
// feature sections cannot honor. Zero remains the documented "use the
// default" value where applicable; a negative value is never reinterpreted.
func validateChangedSectionValues(cfg *Config) error {
	for key, value := range map[string]int{
		"gateway.txt_cache_ttl":   cfg.Gateway.TXTCacheTTL,
		"gateway.txt_stale_grace": cfg.Gateway.TXTStaleGrace,
		"gateway.root_max_age":    cfg.Gateway.RootMaxAge,
	} {
		if value < 0 {
			return fmt.Errorf("%s must not be negative, got %d", key, value)
		}
	}
	for key, value := range map[string]int{
		"content.max_tracked_origins":   cfg.Content.MaxTrackedOrigins,
		"content.max_watched_outpoints": cfg.Content.MaxWatchedOutpoints,
		"content.spend_poll_interval":   cfg.Content.SpendPollInterval,
		"content.tip_pending_timeout":   cfg.Content.TipPendingTimeout,
	} {
		if value < 0 {
			return fmt.Errorf("%s must not be negative, got %d", key, value)
		}
	}
	pay := cfg.API
	for key, value := range map[string]int{
		"payment_satoshis":                pay.PaymentSatoshis,
		"x402_mint_burst":                 pay.X402MintBurst,
		"x402_mints_per_minute":           pay.X402MintsPerMinute,
		"nonce_pool_size":                 pay.NoncePoolSize,
		"app_payments.max_app_price_sats": pay.AppPayments.MaxAppPriceSats,
	} {
		if value < 0 {
			return fmt.Errorf("api.%s must not be negative, got %d", key, value)
		}
	}
	for path, price := range cfg.API.EndpointPrices {
		if price < 0 {
			return fmt.Errorf("api.endpoint_prices[%q] must not be negative, got %d", path, price)
		}
	}
	for _, peer := range cfg.Mesh.AllowedPeers {
		if !isCompressedPubKeyHex(peer) {
			return fmt.Errorf("mesh.allowed_peers: %q is not a valid compressed public key in hex", peer)
		}
	}
	for _, peer := range cfg.Overlay.NamedPeers {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		u, err := url.ParseRequestURI(peer)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("overlay.named_peers: %q is not a valid HTTP(S) base URL", peer)
		}
	}
	return nil
}
