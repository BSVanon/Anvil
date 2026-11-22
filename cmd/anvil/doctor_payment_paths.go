package main

import "github.com/BSVanon/Anvil/internal/config"

func doctorX402DiscoveryCheck(cfg *config.Config, apiURL string) int {
	x402Resp := httpGet(apiURL + "/.well-known/x402")
	if cfg.API.PaymentSatoshis > 0 {
		if x402Resp != nil {
			pass("x402 discovery responding")
			return 0
		}
		fail("x402 discovery not responding (payment_satoshis=%d but /.well-known/x402 returns 404)", cfg.API.PaymentSatoshis)
		return 1
	}
	if x402Resp == nil {
		pass("x402 disabled (payment_satoshis=0)")
	}
	return 0
}

// doctorPaymentPathCheck reports whether configured route prices are published
// by the live x402 discovery document and whether ARC is enabled for the
// production payment paths.
func doctorPaymentPathCheck(cfg *config.Config, apiURL string) int {
	return doctorPaymentPathCheckWithDiscovery(cfg, httpGet(apiURL+"/.well-known/x402"))
}

func doctorPaymentPathCheckWithDiscovery(cfg *config.Config, discovery map[string]interface{}) int {
	if !hasConfiguredRoutePrice(cfg) {
		return 0
	}
	if !cfg.ARC.Enabled {
		if cfg.API.X402ProofScheme && !cfg.API.RequireMempool {
			warn("only the deprecated X402-Proof scheme can take payments because ARC is disabled — enable [arc] for BRC-121 and X-Bsv-Payment")
			return 1
		}
		warn("clients can't pay priced routes because the node refuses BRC-121 and X-Bsv-Payment without ARC — enable [arc]")
		return 1
	}
	if discoveryHasPricedRoute(discovery) {
		pass("priced routes are published in x402 discovery, and ARC is enabled for BRC-121 and X-Bsv-Payment")
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
