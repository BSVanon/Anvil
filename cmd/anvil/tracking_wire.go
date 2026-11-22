package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/gateway"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/migrationmarker"
	"github.com/BSVanon/Anvil/internal/ordtrack"
	"github.com/BSVanon/Anvil/internal/spendwatch"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilversion "github.com/BSVanon/Anvil/internal/version"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// trackedRefreshEvery is how often a gateway reads its policy's origins
// again even when the sites file has not changed, for a domain whose TXT
// record now names another origin.
const trackedRefreshEvery = time.Minute

// trackingDeps is what version tracking takes from main, in this order.
type trackingDeps struct {
	headers     chaintracker.ChainTracker
	proofs      *spv.ProofStore
	fetcher     proofFetcher // an *spv.ProofFetcher
	broadcaster *txrelay.Broadcaster
	gossip      *anvilgossip.Manager // nil without the mesh
	envelopes   *envelope.Store
	key         *ec.PrivateKey // nil: verified tips are not published
}

// wireTracking starts BRC-159 version tracking when [content] track_origins
// lists an origin or [gateway] is on, and returns its tracker. Otherwise it
// returns nil having opened, started and hooked nothing, so a node that
// tracks nothing serves /content and POST /broadcast exactly as before.
func wireTracking(cfg *config.Config, srv *api.Server, logger *slog.Logger, d trackingDeps) *ordtrack.Tracker {
	tracker, _ := startTracking(context.Background(), cfg, srv, logger, d, spendwatch.Config{})
	return tracker
}

// startTracking is wireTracking until ctx ends, its spend watch built from
// watchCfg with [content]'s interval and cap; stop cancels it, waits for
// its loops and closes the tracker's store.
//
// The tracker's store is <data_dir>/ordtrack. It learns tips from every
// transaction the broadcaster admits, from tip envelopes reaching
// /data/subscribe's stream (the mesh's and POST /data's), and from its
// spend watch's polls. It answers /content/<origin>?seq=, takes a tip
// update as its own credential on POST /broadcast, and publishes each tip
// it verifies as an envelope signed by the node's identity key: into the
// envelope store, to the mesh and to /data/subscribe, as POST /data
// publishes one.
func startTracking(ctx context.Context, cfg *config.Config, srv *api.Server, logger *slog.Logger, d trackingDeps, watchCfg spendwatch.Config) (*ordtrack.Tracker, func()) {
	if len(cfg.Content.TrackOrigins) == 0 && !cfg.Gateway.Enabled {
		return nil, func() {}
	}
	if d.headers == nil || d.proofs == nil || d.broadcaster == nil || cfg.Node.DataDir == "" {
		logger.Warn("version tracking not started: no header store, proof store, broadcaster or data_dir")
		return nil, func() {}
	}
	src := &trackSource{proofs: d.proofs, fetcher: d.fetcher, rawTx: srv.ContentServer().RawTx, headers: d.headers}
	watchCfg.PollInterval = time.Duration(cfg.Content.SpendPollInterval) * time.Second
	watchCfg.MaxWatched = cfg.Content.MaxWatchedOutpoints
	watchCfg.Logger = logger
	watch := spendwatch.New(watchCfg)
	tracker, err := ordtrack.New(ordtrack.Config{
		Path:             filepath.Join(cfg.Node.DataDir, "ordtrack"),
		Source:           src,
		Chain:            d.headers,
		Watcher:          watch,
		PendingTimeout:   time.Duration(cfg.Content.TipPendingTimeout) * time.Second,
		MaxOrigins:       cfg.Content.MaxTrackedOrigins,
		Publish:          tipPublisher(srv, d, logger),
		SigningKey:       d.key,
		MaxGossipPayload: cfg.Envelopes.MaxDurableSize,
		Logger:           logger,
		MigrationStarted: migrationmarker.Recorder(cfg.Node.DataDir, anvilversion.Version),
	})
	if err != nil {
		logger.Error("version tracking not started", "error", err)
		return nil, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	var loops sync.WaitGroup
	loops.Add(2)
	go func() { defer loops.Done(); watch.Run(ctx) }()
	go func() { defer loops.Done(); tracker.Run(ctx) }()
	d.broadcaster.SetObserver(func(tx *transaction.Transaction, beef []byte) {
		tracker.NoteBroadcast(tx, beef)
		watch.Observe(tx)
	})
	unsubscribe := srv.SubscribeEnvelopes(ordtrack.TipTopic, tracker.HandleEnvelope)
	srv.ContentServer().SetVersions(tracker, time.Duration(cfg.Gateway.RootMaxAge)*time.Second)
	srv.SetTipCredential(tracker, tracker.Stats)
	if !cfg.Gateway.Enabled {
		// A gateway's set, these and its policy's origins, comes from its
		// policyFollower; until then it keeps the set it had.
		tracker.SetTracked(cfg.Content.TrackOrigins)
	}
	logger.Info("version tracking started", "track_origins", len(cfg.Content.TrackOrigins), "gateway", cfg.Gateway.Enabled)

	var once sync.Once
	return tracker, func() {
		once.Do(func() {
			srv.SetTipCredential(nil, nil)
			srv.ContentServer().SetVersions(nil, 0)
			d.broadcaster.SetObserver(nil)
			unsubscribe()
			cancel()
			loops.Wait()
			_ = tracker.Close()
		})
	}
}

// tipPublisher publishes a tip envelope as POST /data publishes one: into
// the envelope store, then to the mesh and to /data/subscribe.
func tipPublisher(srv *api.Server, d trackingDeps, logger *slog.Logger) func(*envelope.Envelope) {
	return func(env *envelope.Envelope) {
		if d.envelopes != nil {
			if err := d.envelopes.Ingest(env); err != nil {
				logger.Debug("tip envelope not published", "error", err)
				return
			}
		}
		if d.gossip != nil {
			d.gossip.BroadcastEnvelope(env)
		}
		srv.NotifyEnvelope(env)
	}
}

// policyFollower keeps a gateway's tracked set to [content] track_origins
// followed by the origins its policy allows (SetTracked keeps the first
// max_tracked_origins of them): read again whenever the sites file reloads
// with a change, and every trackedRefreshEvery.
type policyFollower struct {
	set        func(origins []string)
	allow      *gateway.Allowlist
	policy     *gateway.Policy
	configured []string
	max        int

	last *gateway.Snapshot
	next time.Time
}

// step reads the policy's origins again when they may have changed, and
// reports whether it did.
func (f *policyFollower) step(ctx context.Context, now time.Time) bool {
	snap := f.allow.Snapshot()
	if snap == f.last && now.Before(f.next) {
		return false
	}
	f.last, f.next = snap, now.Add(trackedRefreshEvery)
	f.set(append(slices.Clone(f.configured), f.policy.TrackedOrigins(ctx, f.max)...))
	return true
}

// run steps every interval, the first time at once, until ctx ends.
func (f *policyFollower) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		f.step(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
