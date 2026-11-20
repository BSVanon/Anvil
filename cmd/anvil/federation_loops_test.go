package main

import (
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/overlay/gaspstatus"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
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

// wireV3Federation itself is covered by federation_wiring_test.go, split
// out to keep this file under the project's line-count cap.
