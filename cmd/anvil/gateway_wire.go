package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
)

// gatewayReloadInterval is how often the sites file's mtime is checked
// for a hot reload — the same shape as main's existing periodic-ticker
// goroutines (e.g. gossip's demand decay), just on its own interval.
const gatewayReloadInterval = 5 * time.Second

// wireGateway returns the handler main's API listener goroutine serves,
// and — when gateway mode is on — also starts the TLS (443) and plain
// (80) listeners gateway mode adds on top of the existing :9333 API
// listener. With [gateway] off (the default), this is exactly
// srv.Handler() — no Router is even constructed, the sites file is
// never read, and startGatewayTLS is never called, so a standard node's
// behaviour stays byte-for-byte what it is today, and nothing listens on
// 80 or 443.
//
// With [gateway] on, it builds the gateway mechanism (internal/gateway's
// Allowlist, Resolver, Policy and SiteHandler) over the node's existing
// content cache and API, wires the gateway counters into the existing
// GET /stats, starts the sites file's hot-reload ticker, starts the
// TLS/plain listeners (gossipMgr may be nil — see startGatewayTLS), and
// returns a Router that sends api_host to the API and every allowed site
// to the SiteHandler; the same Router instance also serves the new 443
// and 80 listeners, so all three listeners agree on what to serve.
func wireGateway(cfg *config.Config, srv *api.Server, logger *slog.Logger, gossipMgr *anvilgossip.Manager) http.Handler {
	if !cfg.Gateway.Enabled {
		return srv.Handler()
	}

	// One Counters shared between the Resolver and the SiteHandler: the
	// TXT-lookup counters (gateway_txt_lookups, gateway_txt_stale_served)
	// are incremented inside the Resolver, but the SiteHandler serves all
	// of these counters from its own Stats() via SetGatewayStats below —
	// so both must increment the same instance.
	counters := &gateway.Counters{}

	allow := gateway.NewAllowlist(cfg.Gateway.SitesFile, cfg.Gateway.APIHost, logger)
	resolver := gateway.NewResolver(gateway.ResolverConfig{
		PositiveTTL: time.Duration(cfg.Gateway.TXTCacheTTL) * time.Second,
		StaleGrace:  time.Duration(cfg.Gateway.TXTStaleGrace) * time.Second,
		Stats:       counters,
	})
	policy := gateway.NewPolicy(allow, resolver)

	sites := gateway.NewSiteHandler(gateway.SiteHandlerConfig{
		Policy:         policy,
		Content:        srv.ContentServer(),
		RootMaxAge:     time.Duration(cfg.Gateway.RootMaxAge) * time.Second,
		ContentScope:   cfg.Gateway.ContentScope,
		TrustProxy:     cfg.API.TrustProxy,
		TrustProxyHops: cfg.API.TrustProxyHops,
		Counters:       counters,
		Logger:         logger,
	})
	srv.SetGatewayStats(sites.Stats)

	go func() {
		ticker := time.NewTicker(gatewayReloadInterval)
		defer ticker.Stop()
		for range ticker.C {
			allow.Reload()
		}
	}()

	router := &gateway.Router{API: srv.Handler(), Sites: sites, APIHost: cfg.Gateway.APIHost}
	startGatewayTLS(cfg, policy, router, counters, gossipMgr, logger)
	return router
}
