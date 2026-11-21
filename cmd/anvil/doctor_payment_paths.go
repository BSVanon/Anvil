package main

import "github.com/BSVanon/Anvil/internal/config"

// doctorPaymentPathCheck warns when configured route prices are not published
// by the live x402 discovery document. Discovery obtains each price from the
// same payment gate that issues challenges, so a positive advertised price is
// evidence that clients have a payment path they can use.
func doctorPaymentPathCheck(cfg *config.Config, apiURL string) int {
	return doctorPaymentPathCheckWithDiscovery(cfg, httpGet(apiURL+"/.well-known/x402"))
}

func doctorPaymentPathCheckWithDiscovery(cfg *config.Config, discovery map[string]interface{}) int {
	if !hasConfiguredRoutePrice(cfg) {
		return 0
	}
	if discoveryHasPricedRoute(discovery) {
		pass("priced routes have an available x402 payment path")
		return 0
	}
	warn("priced routes have no available payment path — check identity, wallet, and payment configuration")
	return 1
}

func hasConfiguredRoutePrice(cfg *config.Config) bool {
	if cfg.API.PaymentSatoshis > 0 {
		return true
	}
	for _, price := range cfg.API.EndpointPrices {
		if price > 0 {
			return true
		}
	}
	return false
}

func discoveryHasPricedRoute(discovery map[string]interface{}) bool {
	endpoints, _ := discovery["endpoints"].([]interface{})
	for _, endpoint := range endpoints {
		route, _ := endpoint.(map[string]interface{})
		if price, _ := route["price"].(float64); price > 0 {
			return true
		}
	}
	return false
}
