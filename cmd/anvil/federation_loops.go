package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/netguard"
	"github.com/BSVanon/Anvil/internal/overlay/federation"
	"github.com/BSVanon/Anvil/internal/overlay/gaspstatus"
	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	goSdkOverlay "github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// overlayNetworkFromBSV returns the canonical overlay network identifier
// used by go-sdk's LookupResolver. Anvil runs on mainnet by default.
// (No testnet config field exists today; we'll add an override when
// testnet operators surface, but the BRC-100 ecosystem is mainnet-only
// in production so this hardcoded default is the right starting point.)
func overlayNetworkFromBSV(_ *config.Config) goSdkOverlay.Network {
	return goSdkOverlay.NetworkMainnet
}

// buildSyncConfiguration constructs the per-topic GASP policy map
// passed to the v3 engine. Every topic the engine currently hosts gets
// SyncConfigurationSHIP so the engine discovers peers via SLAP at sync
// time. tm_ship / tm_slap themselves use SyncConfigurationPeers seeded
// with the bootstrap SHIPTrackers / SLAPTrackers — the engine merges
// those into the peer set at NewEngine time but we set them again here
// so the post-construction upgrade path lands the same shape.
//
// When namedPeers is non-empty ([overlay] named_peers, closed-network
// mode), every topic — not just tm_ship/tm_slap — uses
// SyncConfigurationPeers seeded with namedPeers instead. StartGASPSync
// only runs SHIP-lookup peer discovery for SyncConfigurationSHIP entries
// (engine.go's discoverSHIPPeers), so this skips that discovery
// entirely: GASP catch-up runs straight against the named peers for
// every topic, and no SHIP lookup ever reaches a public or default
// tracker.
//
// ListTopicManagers returns map[topicName]*MetaData; we iterate over
// the keys to enumerate registered topic names.
func buildSyncConfiguration(eng *engine.Engine, namedPeers []string) map[string]engine.SyncConfiguration {
	out := map[string]engine.SyncConfiguration{}
	for name := range eng.ListTopicManagers() {
		switch {
		case len(namedPeers) > 0:
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: namedPeers}
		case name == "tm_ship":
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: eng.SHIPTrackers}
		case name == "tm_slap":
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: eng.SLAPTrackers}
		default:
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationSHIP}
		}
	}
	return out
}

// resolveFederationTrackers decides the SHIPTrackers/SLAPTrackers pair
// wireV3Federation wires into the engine. When namedPeers ([overlay]
// named_peers) is non-empty, it is the sole source of truth: no
// ship_trackers/slap_trackers merge, no DEFAULT_SLAP_TRACKERS fallback —
// every outbound overlay call this wiring enables targets only these
// peers. Otherwise, behaviour is exactly what it was before this setting
// existed: configured ship_trackers/slap_trackers, falling back to
// go-sdk's DEFAULT_SLAP_TRACKERS (overlay-us-1.bsvb.tech,
// overlay-eu-1.bsvb.tech, overlay-ap-1.bsvb.tech, users.bapp.dev) when
// either is left blank.
func resolveFederationTrackers(cfg *config.Config, namedPeers []string) (shipTrackers, slapTrackers []string) {
	if len(namedPeers) > 0 {
		return namedPeers, namedPeers
	}
	slapTrackers = cfg.Overlay.SLAPTrackers
	if len(slapTrackers) == 0 {
		slapTrackers = append(slapTrackers, lookup.DEFAULT_SLAP_TRACKERS...)
	}
	shipTrackers = cfg.Overlay.SHIPTrackers
	if len(shipTrackers) == 0 {
		shipTrackers = append(shipTrackers, lookup.DEFAULT_SLAP_TRACKERS...)
	}
	return shipTrackers, slapTrackers
}

// wireV3Federation wires the v3 engine's canonical BRC-88 federation
// surface (Advertiser, LookupResolver, SHIP/SLAP trackers, GASP
// SyncConfiguration) and starts its periodic loops. Gated exactly as
// before B5: cfg.Overlay.EnableGASPSync must be true and [node]
// public_url must be set, or this is a no-op (adverts still require
// public_url; see internal/overlay/federation/advertiser.go
// FindAllAdvertisements). Called once nodeWallet exists — the caller
// must only call this when nodeWallet != nil.
//
// [overlay] named_peers (closed network): when non-empty, every outbound
// overlay call this wiring enables — GASP sync for every topic, lookup
// federation, submit propagation to interested hosts, and SHIP/SLAP
// resolution — targets only the named peers. ship_trackers /
// slap_trackers and the DEFAULT_SLAP_TRACKERS fallback are not
// consulted; named_peers is the sole source of truth for
// SHIPTrackers/SLAPTrackers in that mode, so the node never contacts a
// baked-in Anvil endpoint or a public tracker. The advertiser's own gate
// (public_url) is unaffected by named_peers, but anything the advertiser
// propagates through Submit also reaches only the named peers, because
// propagation uses the same SLAPTrackers field.
func wireV3Federation(
	cfg *config.Config,
	v3Eng *engine.Engine,
	gaspTracker *gaspstatus.Tracker,
	shipStore *federation.SHIPStorage,
	slapStore *federation.SLAPStorage,
	anvilStore *anvilstorage.Storage,
	nodeWallet *anvilwallet.NodeWallet,
	logger *slog.Logger,
) {
	if v3Eng == nil {
		return
	}
	if !cfg.Overlay.EnableGASPSync {
		logger.Info("v3 federation disabled (cfg.Overlay.EnableGASPSync = false); GASP routes still serve inbound requests")
		return
	}
	if cfg.Node.PublicURL == "" {
		return
	}

	namedPeers := cfg.Overlay.NamedPeers
	shipTrackers, slapTrackers := resolveFederationTrackers(cfg, namedPeers)

	adv := federation.NewAdvertiser(nodeWallet.Wallet(), cfg.Node.PublicURL, shipStore, slapStore, anvilStore)
	// peerhygiene.NewResolver mirrors engine.NewLookupResolverWithNetwork
	// but routes every per-host lookup through a hygiene Facilitator, so
	// dead SLAP/SHIP peers get skipped/backed-off instead of re-queried on
	// every GASP sync + lookup resolution (the federation thrash the DEX saw).
	resolver := peerhygiene.NewResolver(overlayNetworkFromBSV(cfg), logger)
	resolver.SetSLAPTrackers(slapTrackers)
	v3Eng.Advertiser = adv
	v3Eng.LookupResolver = resolver
	v3Eng.SHIPTrackers = shipTrackers
	v3Eng.SLAPTrackers = slapTrackers
	v3Eng.SyncConfiguration = buildSyncConfiguration(v3Eng, namedPeers)
	logger.Info("v3 federation wired",
		"topics", len(v3Eng.SyncConfiguration),
		"trackers", len(slapTrackers),
		"named_peers", len(namedPeers) > 0)

	// Periodic federation work. SyncAdvertisements reconciles our
	// on-chain ad set with the topics we currently host; StartGASPSync
	// pulls peer state for each subscribed topic. Both gated on
	// EnableGASPSync, both safe to run periodically.
	go runSyncAdvertisements(context.Background(), v3Eng, logger, cfg.Overlay.AdvertiseIntervalSecs)
	if gaspTracker != nil {
		gaspTracker.MarkEnabled()
	}
	go runGASPSync(context.Background(), v3Eng, logger, cfg.Overlay.GASPSyncIntervalSecs, gaspTracker)
}

// runSyncAdvertisements ticks engine.SyncAdvertisements at the
// configured cadence. The canonical reconciliation loop creates
// missing SHIP/SLAP outputs for topics we host and revokes ones we no
// longer host. Runs once on boot then on a long cadence —
// advertisement state changes infrequently (operator topic config
// edits), so a tight loop would just churn the wallet. Default 1800s
// (30 min) preserved from v3.0.0; configurable via
// cfg.Overlay.AdvertiseIntervalSecs. Each run is contained: the submit
// it makes propagates through go-sdk code that trusts what peers send,
// so a panic there is logged and the loop goes on.
func runSyncAdvertisements(ctx context.Context, eng *engine.Engine, logger *slog.Logger, intervalSecs int) {
	if intervalSecs <= 0 {
		intervalSecs = 1800
	}
	run := func() error {
		return netguard.Contain(logger, "SyncAdvertisements", func() error { return eng.SyncAdvertisements(ctx) })
	}
	if err := run(); err != nil {
		logger.Error("initial SyncAdvertisements failed", "error", err)
	}
	logger.Info("SyncAdvertisements loop started", "interval_secs", intervalSecs)
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := run(); err != nil {
				logger.Error("SyncAdvertisements failed", "error", err)
			}
		}
	}
}

// runGASPSync ticks engine.StartGASPSync at the configured cadence.
// The canonical sync pulls peer state for each subscribed topic; new
// admits propagate into our local index. v3.0.0-v3.0.6 hardcoded 5 min
// (upstream overlay-express default) which translated to ~3 Mbps
// sustained RX on small VPSes because the canonical engine re-pulls
// advertisements with since=0 each cycle (no cursor persistence yet —
// v3.0.8 candidate work). v3.0.7 makes this configurable + bumps
// default to 1800s (30 min) — cuts bandwidth ~6x without meaningfully
// degrading freshness, since topic admissions aren't high-rate. 0 or
// unset → default 1800. Operators wanting tighter discovery can dial
// down; aim for 60s as a practical floor. Each run is contained, as in
// runSyncAdvertisements: its SHIP lookups and peer fetches run go-sdk
// code that trusts what peers send.
func runGASPSync(ctx context.Context, eng *engine.Engine, logger *slog.Logger, intervalSecs int, tracker *gaspstatus.Tracker) {
	if intervalSecs <= 0 {
		intervalSecs = 1800
	}
	run := func() error {
		return netguard.Contain(logger, "StartGASPSync", func() error { return eng.StartGASPSync(ctx) })
	}
	if err := run(); err != nil {
		logger.Error("initial StartGASPSync failed", "error", err)
	} else if tracker != nil {
		tracker.RecordSuccess()
	}
	logger.Info("GASPSync loop started", "interval_secs", intervalSecs)
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := run(); err != nil {
				logger.Error("StartGASPSync failed", "error", err)
			} else if tracker != nil {
				tracker.RecordSuccess()
			}
		}
	}
}
