package api

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/libsv/go-p2p/wire"
)

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
	var fresh func(time.Time) bool
	if cfg.HeaderStore != nil && cfg.HeaderStaleAfterSecs > 0 {
		fresh = func(now time.Time) bool {
			raw, err := cfg.HeaderStore.HeaderAtHeight(cfg.HeaderStore.Tip())
			if err != nil {
				return false
			}
			var h wire.BlockHeader
			if err := h.Deserialize(bytes.NewReader(raw)); err != nil {
				return false
			}
			return now.Unix()-h.Timestamp.Unix() <= int64(cfg.HeaderStaleAfterSecs)
		}
	}
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:        cfg.PaymentSatoshis,
		PayeeScriptHex:   cfg.PayeeScriptHex,
		NonceProvider:    cfg.NonceProvider,
		NoProofScheme:    cfg.NoProofScheme,
		RequireMempool:   cfg.RequireMempool,
		ARCClient:        cfg.ARCClient,
		Resolver:         resolver,
		AllowPassthrough: cfg.AllowPassthrough,
		AllowSplit:       cfg.AllowSplit,
		MaxAppPriceSats:  cfg.MaxAppPriceSats,
		EndpointPrices:   cfg.EndpointPrices,
		HeaderTip:        tip,
		HeaderAtHeight: func(height uint32) ([]byte, error) {
			if cfg.HeaderStore == nil {
				return nil, fmt.Errorf("no header store")
			}
			return cfg.HeaderStore.HeaderAtHeight(height)
		},
		HeadersFresh: fresh,
	})
	if pg != nil { // nil when the node takes no payment
		pg.clientKey = func(r *http.Request) string {
			return rateLimitKey(clientIP(r, cfg.TrustProxy, cfg.TrustProxyHops))
		}
		// BRC-121 needs the node wallet, ARC, the SPV validator and the
		// data directory for its journal (brc121.go).
		if err := pg.enableBRC121(cfg.Wallet, cfg.Validator, cfg.DataDir, cfg.Logger); err != nil && cfg.Logger != nil {
			cfg.Logger.Warn("BRC-121 payments are off", "error", err)
		}
	}
	return pg
}
