package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/gaspstatus"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
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
