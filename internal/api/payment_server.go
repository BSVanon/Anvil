package api

import "net/http"

// newServerPaymentGate builds the server's payment gate from its config. The
// header store's tip backs the depth check on direct payments
// (checkPaymentDepth, payment_arc.go); a server with no header store has no
// tip, and refuses every direct payment ARC reports as mined. A client's
// payment body reads are shared out under the key the server's rate limiter
// gives that client, with the same trust_proxy settings
// (payment_bodyshare.go).
func newServerPaymentGate(cfg ServerConfig, resolver *TopicMonetizationResolver) *PaymentGate {
	var tip func() uint32
	if cfg.HeaderStore != nil {
		tip = cfg.HeaderStore.Tip
	}
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:        cfg.PaymentSatoshis,
		PayeeScriptHex:   cfg.PayeeScriptHex,
		NonceProvider:    cfg.NonceProvider,
		RequireMempool:   cfg.RequireMempool,
		ARCClient:        cfg.ARCClient,
		Resolver:         resolver,
		AllowPassthrough: cfg.AllowPassthrough,
		AllowSplit:       cfg.AllowSplit,
		MaxAppPriceSats:  cfg.MaxAppPriceSats,
		EndpointPrices:   cfg.EndpointPrices,
		HeaderTip:        tip,
	})
	if pg != nil { // nil when the node takes no payment
		pg.clientKey = func(r *http.Request) string {
			return rateLimitKey(clientIP(r, cfg.TrustProxy, cfg.TrustProxyHops))
		}
	}
	return pg
}
