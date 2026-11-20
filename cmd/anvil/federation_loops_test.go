package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/headers"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/federation"
	"github.com/BSVanon/Anvil/internal/overlay/gaspstatus"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// panickingAdvertiser panics on the first call SyncAdvertisements makes, as
// go-sdk code reading a hostile peer's reply can panic inside a sync run.
type panickingAdvertiser struct{ calls *atomic.Int64 }

func (a panickingAdvertiser) FindAllAdvertisements(overlay.Protocol) ([]*advertiser.Advertisement, error) {
	a.calls.Add(1)
	panic("advertiser panicked")
}

func (panickingAdvertiser) CreateAdvertisements([]*advertiser.AdvertisementData) (overlay.TaggedBEEF, error) {
	return overlay.TaggedBEEF{}, nil
}

func (panickingAdvertiser) RevokeAdvertisements([]*advertiser.Advertisement) (overlay.TaggedBEEF, error) {
	return overlay.TaggedBEEF{}, nil
}

func (panickingAdvertiser) ParseAdvertisement(*script.Script) (*advertiser.Advertisement, error) {
	return nil, nil
}

// panickingResolver panics when StartGASPSync's SHIP peer discovery uses it.
type panickingResolver struct{ calls *atomic.Int64 }

func (r panickingResolver) SLAPTrackers() []string { return nil }

func (r panickingResolver) SetSLAPTrackers([]string) {
	r.calls.Add(1)
	panic("resolver panicked")
}

func (r panickingResolver) Query(context.Context, *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return nil, nil
}

// syncBuffer is a log destination safe for the loop goroutine and the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runLoopUntil runs loop in a goroutine until calls reaches 2 (the run at
// start and the first tick, a second later), then cancels it and waits for it
// to return. A panic in a run would end the test binary instead.
func runLoopUntil(t *testing.T, calls *atomic.Int64, loop func(ctx context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		loop(ctx)
	}()
	for deadline := time.Now().Add(10 * time.Second); calls.Load() < 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("the loop made %d runs in 10s, want 2", calls.Load())
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not return once its context ended")
	}
}

// TestRunSyncAdvertisements_SurvivesAPanickingRun: a panic inside a sync run
// is logged with its site and stack, counts as that run's failure, and the
// loop goes on to its next tick.
func TestRunSyncAdvertisements_SurvivesAPanickingRun(t *testing.T) {
	var calls atomic.Int64
	var logged syncBuffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	eng := &engine.Engine{Advertiser: panickingAdvertiser{calls: &calls}}
	runLoopUntil(t, &calls, func(ctx context.Context) { runSyncAdvertisements(ctx, eng, logger, 1) })
	out := logged.String()
	for _, want := range []string{"site=SyncAdvertisements", "panic=\"advertiser panicked\"", "initial SyncAdvertisements failed", "msg=\"SyncAdvertisements failed\"", "panickingAdvertiser"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
}

// TestRunGASPSync_SurvivesAPanickingRun: the same for the GASP sync loop, and
// a run that panicked is not recorded as a successful sync.
func TestRunGASPSync_SurvivesAPanickingRun(t *testing.T) {
	var calls atomic.Int64
	var logged syncBuffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	eng := &engine.Engine{
		SyncConfiguration: map[string]engine.SyncConfiguration{"tm_test": {Type: engine.SyncConfigurationSHIP}},
		LookupResolver:    panickingResolver{calls: &calls},
	}
	tracker := gaspstatus.New(1)
	runLoopUntil(t, &calls, func(ctx context.Context) { runGASPSync(ctx, eng, logger, 1, tracker) })
	out := logged.String()
	for _, want := range []string{"site=StartGASPSync", "panic=\"resolver panicked\"", "initial StartGASPSync failed", "msg=\"StartGASPSync failed\"", "panickingResolver"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
	if tracker.Snapshot().InitialSyncDone {
		t.Error("a run that panicked was recorded as a successful sync")
	}
}

// TestRunSyncAdvertisements_UnfundedWalletLogsClearlyAndKeepsRunning is
// item 9 (K3/F5): what happens when the node wallet cannot afford the
// SHIP/SLAP adverts for tm_messagebox/ls_messagebox (or any other
// topic). A real, freshly-created NodeWallet (a fresh WIF, never funded
// by any deposit or internalized transaction -- zero balance by
// construction, exactly the "a few sats" live-node case item 9 asks
// about) is wired as a real federation.Advertiser against a real
// v3engine.New instance, then SyncAdvertisements is called directly,
// with slog's process-wide default temporarily redirected to a buffer:
// go-overlay-services' own SyncAdvertisements logs a failure via the
// bare package-level slog.Error, i.e. slog.Default() -- the same logger
// cmd/anvil's own main.go uses (`logger := slog.Default()`, main.go:105;
// no slog.SetDefault call anywhere in cmd/anvil), so this redirect
// observes exactly what a real node's own log stream would show.
//
// Found: SyncAdvertisements (go-overlay-services engine.go:888-953)
// never returns the CreateAdvertisements error to its caller -- it logs
// and swallows it, returning nil. The underlying failure is
// go-wallet-toolbox's own insufficient-funds error
// (pkg/storage/internal/actions/create.go:268, wrapping
// pkg/internal/storage/funder/errfunder.ErrNotEnoughFunds, "not enough
// funds"), wrapped once more by
// internal/overlay/federation/advertiser.go's CreateAdvertisements
// (":161", "federation: advertiser: create action: %w"). So: no crash
// (SyncAdvertisements returns nil; runSyncAdvertisements's own retry
// cadence is cfg.Overlay.AdvertiseIntervalSecs, default 1800s -- never a
// 1-second storm, confirmed separately by this file's sibling
// TestRunSyncAdvertisements_SurvivesAPanickingRun for that loop's panic
// recovery), the node keeps serving (the engine is still fully usable
// afterward), and the log line that does fire names the real cause
// clearly enough for an operator to act on. No cmd/anvil fix was needed
// -- this test exists to prove, not assume, that finding, and to catch
// a regression in either the swallow-and-log behaviour or the error's
// clarity.
func TestRunSyncAdvertisements_UnfundedWalletLogsClearlyAndKeepsRunning(t *testing.T) {
	root := t.TempDir()

	hs, err := headers.NewTestStore(filepath.Join(root, "h"))
	if err != nil {
		t.Fatalf("headers.NewTestStore: %v", err)
	}
	t.Cleanup(func() { _ = hs.Close() })
	ps, err := spv.NewProofStore(filepath.Join(root, "proofs"))
	if err != nil {
		t.Fatalf("spv.NewProofStore: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	mempool := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mempool, nil, slog.Default())

	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	walletDir := filepath.Join(root, "wallet")
	if err := os.MkdirAll(walletDir, 0o755); err != nil {
		t.Fatalf("mkdir wallet dir: %v", err)
	}
	nw, err := anvilwallet.New(priv.Wif(), walletDir, hs, ps, broadcaster, nil, slog.Default())
	if err != nil {
		t.Fatalf("anvilwallet.New: %v", err)
	}
	t.Cleanup(nw.Close)

	dir, err := anviloverlay.NewDirectory(filepath.Join(root, "overlay"))
	if err != nil {
		t.Fatalf("open overlay directory: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	overlaytest.SeedFundingBlock(t, hs)
	eng, err := v3engine.New(&v3engine.Config{
		Storage:      anvilstorage.New(dir.DB()),
		HeadersStore: hs,
		LookupDB:     dir.DB(),
		HostingURL:   "https://my-anvil.example.org",
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	eng.Advertiser = federation.NewAdvertiser(nw.Wallet(), "https://my-anvil.example.org",
		federation.NewSHIPStorage(dir.DB()), federation.NewSLAPStorage(dir.DB()), anvilstorage.New(dir.DB()))

	var logged syncBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	if err := eng.SyncAdvertisements(context.Background()); err != nil {
		t.Fatalf("SyncAdvertisements returned an error instead of swallowing it: %v", err)
	}

	// The node must still serve: a basic, already-exercised-elsewhere
	// engine call must still work afterward -- a crash or corrupted
	// engine state would show up here.
	if _, ok := eng.GetLookupService(topics.MessageBoxLookupServiceName); !ok {
		t.Fatal("engine lost its registered ls_messagebox lookup service after SyncAdvertisements -- it should still be serving")
	}

	out := logged.String()
	if !strings.Contains(out, "failed to create SHIP/SLAP advertisements") {
		t.Fatalf("expected a clear warning naming SHIP/SLAP advertisement creation; got:\n%s", out)
	}
	if !strings.Contains(out, "not enough funds") {
		t.Fatalf("expected the warning to name the real cause (not enough funds); got:\n%s", out)
	}
}

// stubTopicManager satisfies engine.TopicManager with trivial bodies, only
// to give buildSyncConfiguration's tests topic names to iterate over via
// eng.ListTopicManagers().
type stubTopicManager struct{}

func (stubTopicManager) IdentifyAdmissibleOutputs(context.Context, *transaction.Beef, *chainhash.Hash, []uint32) (overlay.AdmittanceInstructions, error) {
	return overlay.AdmittanceInstructions{}, nil
}

func (stubTopicManager) IdentifyNeededInputs(context.Context, *transaction.Beef, *chainhash.Hash) ([]*transaction.Outpoint, error) {
	return nil, nil
}

func (stubTopicManager) GetDocumentation() string { return "" }

func (stubTopicManager) GetMetaData() *overlay.MetaData { return &overlay.MetaData{} }

// newSyncConfigTestEngine builds a bare engine.Engine (no storage, no real
// admission) with the given topic names registered and the given bootstrap
// trackers -- everything buildSyncConfiguration reads.
func newSyncConfigTestEngine(topicNames []string, shipTrackers, slapTrackers []string) *engine.Engine {
	managers := make(map[string]engine.TopicManager, len(topicNames))
	for _, name := range topicNames {
		managers[name] = stubTopicManager{}
	}
	return engine.NewEngine(&engine.Config{
		Managers:     managers,
		SHIPTrackers: shipTrackers,
		SLAPTrackers: slapTrackers,
	})
}

// TestBuildSyncConfiguration_NamedPeersForcesEveryTopicToPeers is the
// mutation check for [overlay] named_peers' GASP-sync requirement: when
// namedPeers is non-empty, EVERY topic the engine hosts -- including
// tm_ship and tm_slap, not just arbitrary data topics -- gets
// SyncConfigurationPeers seeded with exactly namedPeers, never the
// bootstrap SHIPTrackers/SLAPTrackers and never go-sdk's
// DEFAULT_SLAP_TRACKERS fallback.
func TestBuildSyncConfiguration_NamedPeersForcesEveryTopicToPeers(t *testing.T) {
	eng := newSyncConfigTestEngine(
		[]string{"tm_ship", "tm_slap", "tm_uhrp"},
		[]string{"https://bootstrap-ship.example"},
		[]string{"https://bootstrap-slap.example"},
	)
	namedPeers := []string{"https://named-a.example", "https://named-b.example"}

	got := buildSyncConfiguration(eng, namedPeers)

	if len(got) != 3 {
		t.Fatalf("expected 3 topics in the sync configuration, got %d: %+v", len(got), got)
	}
	for _, name := range []string{"tm_ship", "tm_slap", "tm_uhrp"} {
		cfg, ok := got[name]
		if !ok {
			t.Fatalf("topic %q missing from sync configuration", name)
		}
		if cfg.Type != engine.SyncConfigurationPeers {
			t.Errorf("topic %q: Type = %v, want SyncConfigurationPeers", name, cfg.Type)
		}
		if !reflect.DeepEqual(cfg.Peers, namedPeers) {
			t.Errorf("topic %q: Peers = %v, want %v (bootstrap trackers must not be merged in)", name, cfg.Peers, namedPeers)
		}
	}
}

// TestBuildSyncConfiguration_UnsetPreservesOriginalBehavior is the mutation
// check for the hard constraint that named_peers empty/unset leaves
// today's GASP sync configuration byte for byte unchanged: tm_ship and
// tm_slap keep using SyncConfigurationPeers seeded with the engine's own
// bootstrap SHIPTrackers/SLAPTrackers, and every other topic keeps using
// SyncConfigurationSHIP (peer discovery via SHIP lookup at sync time).
func TestBuildSyncConfiguration_UnsetPreservesOriginalBehavior(t *testing.T) {
	shipTrackers := []string{"https://bootstrap-ship.example"}
	slapTrackers := []string{"https://bootstrap-slap.example"}
	eng := newSyncConfigTestEngine([]string{"tm_ship", "tm_slap", "tm_uhrp"}, shipTrackers, slapTrackers)

	for _, namedPeers := range [][]string{nil, {}} {
		got := buildSyncConfiguration(eng, namedPeers)

		if cfg := got["tm_ship"]; cfg.Type != engine.SyncConfigurationPeers || !reflect.DeepEqual(cfg.Peers, shipTrackers) {
			t.Errorf("namedPeers=%#v: tm_ship = %+v, want {SyncConfigurationPeers, %v}", namedPeers, cfg, shipTrackers)
		}
		if cfg := got["tm_slap"]; cfg.Type != engine.SyncConfigurationPeers || !reflect.DeepEqual(cfg.Peers, slapTrackers) {
			t.Errorf("namedPeers=%#v: tm_slap = %+v, want {SyncConfigurationPeers, %v}", namedPeers, cfg, slapTrackers)
		}
		if cfg := got["tm_uhrp"]; cfg.Type != engine.SyncConfigurationSHIP {
			t.Errorf("namedPeers=%#v: tm_uhrp.Type = %v, want SyncConfigurationSHIP", namedPeers, cfg.Type)
		}
	}
}

// TestResolveFederationTrackers_NamedPeersIsSoleSource is the mutation
// check for the named_peers half of wireV3Federation's tracker selection:
// when [overlay] named_peers is set, both SHIPTrackers and SLAPTrackers
// come from it alone, even when ship_trackers/slap_trackers are also
// configured -- they must not be merged in.
func TestResolveFederationTrackers_NamedPeersIsSoleSource(t *testing.T) {
	cfg := &config.Config{}
	cfg.Overlay.SLAPTrackers = []string{"https://configured-slap.example"}
	cfg.Overlay.SHIPTrackers = []string{"https://configured-ship.example"}
	namedPeers := []string{"https://named-a.example", "https://named-b.example"}

	shipTrackers, slapTrackers := resolveFederationTrackers(cfg, namedPeers)

	if !reflect.DeepEqual(shipTrackers, namedPeers) {
		t.Errorf("shipTrackers = %v, want %v (configured ship_trackers must not be merged in)", shipTrackers, namedPeers)
	}
	if !reflect.DeepEqual(slapTrackers, namedPeers) {
		t.Errorf("slapTrackers = %v, want %v (configured slap_trackers must not be merged in)", slapTrackers, namedPeers)
	}
}

// TestResolveFederationTrackers_UnsetPreservesOriginalBehavior is the
// mutation check for the hard constraint that named_peers empty/unset
// leaves today's tracker resolution unchanged: configured
// ship_trackers/slap_trackers win when set, and go-sdk's
// DEFAULT_SLAP_TRACKERS is the fallback when either is blank -- exactly as
// before this setting existed.
func TestResolveFederationTrackers_UnsetPreservesOriginalBehavior(t *testing.T) {
	for _, namedPeers := range [][]string{nil, {}} {
		t.Run("configured_trackers_win", func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Overlay.SLAPTrackers = []string{"https://configured-slap.example"}
			cfg.Overlay.SHIPTrackers = []string{"https://configured-ship.example"}

			shipTrackers, slapTrackers := resolveFederationTrackers(cfg, namedPeers)

			if !reflect.DeepEqual(shipTrackers, cfg.Overlay.SHIPTrackers) {
				t.Errorf("shipTrackers = %v, want configured %v", shipTrackers, cfg.Overlay.SHIPTrackers)
			}
			if !reflect.DeepEqual(slapTrackers, cfg.Overlay.SLAPTrackers) {
				t.Errorf("slapTrackers = %v, want configured %v", slapTrackers, cfg.Overlay.SLAPTrackers)
			}
		})
		t.Run("blank_falls_back_to_default_slap_trackers", func(t *testing.T) {
			cfg := &config.Config{} // ship_trackers/slap_trackers both blank

			shipTrackers, slapTrackers := resolveFederationTrackers(cfg, namedPeers)

			if !reflect.DeepEqual(shipTrackers, lookup.DEFAULT_SLAP_TRACKERS) {
				t.Errorf("shipTrackers = %v, want go-sdk's DEFAULT_SLAP_TRACKERS %v", shipTrackers, lookup.DEFAULT_SLAP_TRACKERS)
			}
			if !reflect.DeepEqual(slapTrackers, lookup.DEFAULT_SLAP_TRACKERS) {
				t.Errorf("slapTrackers = %v, want go-sdk's DEFAULT_SLAP_TRACKERS %v", slapTrackers, lookup.DEFAULT_SLAP_TRACKERS)
			}
		})
	}
}

// wireV3Federation itself (B5 fix pass, review BLOCKER 1) is covered by
// federation_wiring_test.go, split out to keep this file under the
// project's line-count cap.
