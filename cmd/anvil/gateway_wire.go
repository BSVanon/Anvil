package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
)

// gatewayReloadInterval is decision 7's "the service checks the file's
// mtime every 5s" — the same shape as main's existing periodic-ticker
// goroutines (e.g. gossip's demand decay), just on its own interval.
const gatewayReloadInterval = 5 * time.Second

// wireGateway returns the handler main's API listener goroutine serves.
// With [gateway] off (the default), this is exactly srv.Handler() — no
// Router is even constructed, and the sites file is never read, so a
// standard node's behaviour stays byte-for-byte what it is today.
//
// With [gateway] on, it builds the gateway mechanism (internal/gateway's
// Allowlist, Resolver, Policy and SiteHandler) over the node's existing
// content cache and API, wires decision 8's counters into the existing
// GET /stats, starts the sites file's hot-reload ticker, and returns a
// Router that sends api_host to the API and every allowed site to the
// SiteHandler.
func wireGateway(cfg *config.Config, srv *api.Server, logger *slog.Logger) http.Handler {
	if !cfg.Gateway.Enabled {
		return srv.Handler()
	}

	// One Counters shared between the Resolver and the SiteHandler: the
	// TXT-lookup counters (gateway_txt_lookups, gateway_txt_stale_served)
	// are incremented inside the Resolver, but decision 8 serves all five
	// counters from the SiteHandler's Stats() via SetGatewayStats below —
	// so both must increment the same instance.
	counters := &gateway.Counters{}

	allow := gateway.NewAllowlist(cfg.Gateway.SitesFile, logger)
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

	return &gateway.Router{API: srv.Handler(), Sites: sites, APIHost: cfg.Gateway.APIHost}
}
