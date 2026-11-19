package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/netguard"
	"github.com/BSVanon/Anvil/internal/overlay/gaspstatus"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	goSdkOverlay "github.com/bsv-blockchain/go-sdk/overlay"
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
// ListTopicManagers returns map[topicName]*MetaData; we iterate over
// the keys to enumerate registered topic names.
func buildSyncConfiguration(eng *engine.Engine) map[string]engine.SyncConfiguration {
	out := map[string]engine.SyncConfiguration{}
	for name := range eng.ListTopicManagers() {
		switch name {
		case "tm_ship":
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: eng.SHIPTrackers}
		case "tm_slap":
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationPeers, Peers: eng.SLAPTrackers}
		default:
			out[name] = engine.SyncConfiguration{Type: engine.SyncConfigurationSHIP}
		}
	}
	return out
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
