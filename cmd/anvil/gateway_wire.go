package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/ordtrack"
)

// gatewayReloadInterval is how often the sites file's mtime is checked
// for a hot reload — the same shape as main's existing periodic-ticker
// goroutines (e.g. gossip's demand decay), just on its own interval.
const gatewayReloadInterval = 5 * time.Second

// wireGateway returns the handler main's API listener goroutine serves,
// once it has started version tracking where the node tracks versions
// (wireTracking, given deps): gatewayHandler's, with that tracker and the
// mesh manager in deps.
func wireGateway(cfg *config.Config, srv *api.Server, logger *slog.Logger, deps trackingDeps) http.Handler {
	return gatewayHandler(context.Background(), cfg, srv, logger, wireTracking(cfg, srv, logger, deps), deps.gossip)
}

// gatewayHandler: with [gateway] off (the default), this is exactly
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
// and 80 listeners, so all three listeners agree on what to serve. A
// non-nil tracker serves the sites' versions and, until ctx ends, tracks
// every origin the policy allows.
func gatewayHandler(ctx context.Context, cfg *config.Config, srv *api.Server, logger *slog.Logger, tracker *ordtrack.Tracker, gossipMgr *anvilgossip.Manager) http.Handler {
	if !cfg.Gateway.Enabled {
		return srv.Handler()
	}

	// One Counters shared between the Resolver and the SiteHandler: the
	// TXT-lookup counters (gateway_txt_lookups, gateway_txt_stale_served)
	// are incremented inside the Resolver, but the SiteHandler serves all
	// of these counters from its own Stats() via SetGatewayStats below —
	// so both must increment the same instance.
	counters := &gateway.Counters{}

	allow := gateway.NewAllowlistWithRegistrations(
		cfg.Gateway.SitesFile,
		gateway.RegistrationFile(cfg.Node.DataDir),
		cfg.Gateway.APIHost,
		logger,
	)
	srv.SetGatewayRegistrationReload(allow.Reload)
	resolver := gateway.NewResolver(gateway.ResolverConfig{
		PositiveTTL: time.Duration(cfg.Gateway.TXTCacheTTL) * time.Second,
		StaleGrace:  time.Duration(cfg.Gateway.TXTStaleGrace) * time.Second,
		Stats:       counters,
	})
	policy := gateway.NewPolicy(allow, resolver)

	// Sites serve their versions from the tracker, which tracks every
	// origin the policy allows.
	var versions gateway.Versions
	if tracker != nil {
		versions = tracker
		f := &policyFollower{set: tracker.SetTracked, allow: allow, policy: policy, configured: cfg.Content.TrackOrigins, max: cfg.Content.MaxTrackedOrigins}
		go f.run(ctx, gatewayReloadInterval)
	}
	sites := gateway.NewSiteHandler(gateway.SiteHandlerConfig{
		Policy:         policy,
		Content:        srv.ContentServer(),
		Versions:       versions,
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
