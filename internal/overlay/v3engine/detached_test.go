package v3engine

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/health"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/ship"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/slap"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// carriedKey keys the value the wrapper tests put on the caller's context.
type carriedKey struct{}

// seenCtx is what one call's context looked like when it reached the
// recording store or service.
type seenCtx struct {
	err   error
	value any
}

// recorder notes the context each method receives, by method name.
type recorder map[string]seenCtx

func (r recorder) note(method string, ctx context.Context) {
	r[method] = seenCtx{err: ctx.Err(), value: ctx.Value(carriedKey{})}
}

// recordingStorage implements engine.Storage by recording each call's
// context. It embeds nothing, so a method added to engine.Storage breaks this
// file's build as it breaks detached.go's.
type recordingStorage struct{ seen recorder }

func (r recordingStorage) InsertOutputs(ctx context.Context, _ string, _ *chainhash.Hash, _ []uint32, _ []*transaction.Outpoint, _ *transaction.Beef, _ []*chainhash.Hash) error {
	r.seen.note("InsertOutputs", ctx)
	return nil
}

func (r recordingStorage) FindOutput(ctx context.Context, _ *transaction.Outpoint, _ *string, _ *bool, _ bool) (*engine.Output, error) {
	r.seen.note("FindOutput", ctx)
	return nil, nil
}

func (r recordingStorage) FindOutputs(ctx context.Context, _ []*transaction.Outpoint, _ string, _ *bool, _ bool) ([]*engine.Output, error) {
	r.seen.note("FindOutputs", ctx)
	return nil, nil
}

func (r recordingStorage) FindOutputsForTransaction(ctx context.Context, _ *chainhash.Hash, _ bool) ([]*engine.Output, error) {
	r.seen.note("FindOutputsForTransaction", ctx)
	return nil, nil
}

func (r recordingStorage) FindUTXOsForTopic(ctx context.Context, _ string, _ float64, _ uint32, _ bool) ([]*engine.Output, error) {
	r.seen.note("FindUTXOsForTopic", ctx)
	return nil, nil
}

func (r recordingStorage) DeleteOutput(ctx context.Context, _ *transaction.Outpoint, _ string) error {
	r.seen.note("DeleteOutput", ctx)
	return nil
}

func (r recordingStorage) MarkUTXOsAsSpent(ctx context.Context, _ []*transaction.Outpoint, _ string, _ *chainhash.Hash) error {
	r.seen.note("MarkUTXOsAsSpent", ctx)
	return nil
}

func (r recordingStorage) UpdateConsumedBy(ctx context.Context, _ *transaction.Outpoint, _ string, _ []*transaction.Outpoint) error {
	r.seen.note("UpdateConsumedBy", ctx)
	return nil
}

func (r recordingStorage) UpdateTransactionBEEF(ctx context.Context, _ *chainhash.Hash, _ *transaction.Beef) error {
	r.seen.note("UpdateTransactionBEEF", ctx)
	return nil
}

func (r recordingStorage) UpdateOutputBlockHeight(ctx context.Context, _ *transaction.Outpoint, _ string, _ uint32, _ uint64) error {
	r.seen.note("UpdateOutputBlockHeight", ctx)
	return nil
}

func (r recordingStorage) InsertAppliedTransaction(ctx context.Context, _ *overlay.AppliedTransaction) error {
	r.seen.note("InsertAppliedTransaction", ctx)
	return nil
}

func (r recordingStorage) DoesAppliedTransactionExist(ctx context.Context, _ *overlay.AppliedTransaction) (bool, error) {
	r.seen.note("DoesAppliedTransactionExist", ctx)
	return false, nil
}

func (r recordingStorage) UpdateLastInteraction(ctx context.Context, _, _ string, _ float64) error {
	r.seen.note("UpdateLastInteraction", ctx)
	return nil
}

func (r recordingStorage) GetLastInteraction(ctx context.Context, _, _ string) (float64, error) {
	r.seen.note("GetLastInteraction", ctx)
	return 0, nil
}

func (r recordingStorage) FindOutpointsByMerkleState(ctx context.Context, _ string, _ engine.MerkleState, _ uint32) ([]*transaction.Outpoint, error) {
	r.seen.note("FindOutpointsByMerkleState", ctx)
	return nil, nil
}

func (r recordingStorage) ReconcileMerkleRoot(ctx context.Context, _ string, _ uint32, _ *chainhash.Hash) error {
	r.seen.note("ReconcileMerkleRoot", ctx)
	return nil
}

func (r recordingStorage) LoadAncillaryBeef(ctx context.Context, _ *engine.Output) error {
	r.seen.note("LoadAncillaryBeef", ctx)
	return nil
}

// recordingLookup implements engine.LookupService by recording each call's
// context; its notifications return err. It embeds nothing.
type recordingLookup struct {
	seen recorder
	err  error
	meta *overlay.MetaData
}

func (r recordingLookup) OutputAdmittedByTopic(ctx context.Context, _ *engine.OutputAdmittedByTopic) error {
	r.seen.note("OutputAdmittedByTopic", ctx)
	return r.err
}

func (r recordingLookup) OutputSpent(ctx context.Context, _ *engine.OutputSpent) error {
	r.seen.note("OutputSpent", ctx)
	return r.err
}

func (r recordingLookup) OutputNoLongerRetainedInHistory(ctx context.Context, _ *transaction.Outpoint, _ string) error {
	r.seen.note("OutputNoLongerRetainedInHistory", ctx)
	return r.err
}

func (r recordingLookup) OutputEvicted(ctx context.Context, _ *transaction.Outpoint) error {
	r.seen.note("OutputEvicted", ctx)
	return r.err
}

func (r recordingLookup) OutputBlockHeightUpdated(ctx context.Context, _ *chainhash.Hash, _ uint32, _ uint64) error {
	r.seen.note("OutputBlockHeightUpdated", ctx)
	return r.err
}

func (r recordingLookup) Lookup(ctx context.Context, _ *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	r.seen.note("Lookup", ctx)
	return &lookup.LookupAnswer{}, nil
}

func (r recordingLookup) GetDocumentation() string       { return "recording lookup" }
func (r recordingLookup) GetMetaData() *overlay.MetaData { return r.meta }

// cancelledCtx is a caller's context that is already cancelled and carries a
// value the wrapped store or service must still see.
func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), carriedKey{}, "carried"))
	cancel()
	return ctx
}

// assertCalls runs calls[m] for every method m of iface and fails unless each
// reached seen with a context that is live (wantLive) or cancelled, carrying
// the caller's value. skip names methods the caller checks itself.
func assertCalls(t *testing.T, iface reflect.Type, calls map[string]func(), seen recorder, wantLive bool, skip ...string) {
	t.Helper()
	covered := len(skip)
	for i := range iface.NumMethod() {
		name := iface.Method(i).Name
		if slices.Contains(skip, name) {
			continue
		}
		call, ok := calls[name]
		if !ok {
			t.Errorf("no call for %s.%s", iface.Name(), name)
			continue
		}
		covered++
		call()
		got, ok := seen[name]
		switch {
		case !ok:
			t.Errorf("%s did not reach the wrapped %s", name, iface.Name())
		case wantLive && got.err != nil:
			t.Errorf("%s reached the wrapped %s with a cancelled context: %v", name, iface.Name(), got.err)
		case !wantLive && !errors.Is(got.err, context.Canceled):
			t.Errorf("%s reached the wrapped %s without the caller's cancellation (%v)", name, iface.Name(), got.err)
		case got.value != "carried":
			t.Errorf("%s reached the wrapped %s without the caller's context values", name, iface.Name())
		}
	}
	if covered != iface.NumMethod() || len(calls)+len(skip) != iface.NumMethod() {
		t.Errorf("the table covers %d calls and %d skips for %s's %d methods", len(calls), len(skip), iface.Name(), iface.NumMethod())
	}
}

// TestDetachedStorage_EveryMethodIgnoresCancellation: every engine.Storage
// method of the engine's view must reach the store with a live context even
// when the caller's is cancelled, and with the caller's values, in which the
// legacy shim's commit notifier rides.
func TestDetachedStorage_EveryMethodIgnoresCancellation(t *testing.T) {
	seen := recorder{}
	view := detachedStorage{inner: recordingStorage{seen: seen}}
	ctx := cancelledCtx()
	calls := map[string]func(){
		"InsertOutputs":               func() { _ = view.InsertOutputs(ctx, "", nil, nil, nil, nil, nil) },
		"FindOutput":                  func() { _, _ = view.FindOutput(ctx, nil, nil, nil, false) },
		"FindOutputs":                 func() { _, _ = view.FindOutputs(ctx, nil, "", nil, false) },
		"FindOutputsForTransaction":   func() { _, _ = view.FindOutputsForTransaction(ctx, nil, false) },
		"FindUTXOsForTopic":           func() { _, _ = view.FindUTXOsForTopic(ctx, "", 0, 0, false) },
		"DeleteOutput":                func() { _ = view.DeleteOutput(ctx, nil, "") },
		"MarkUTXOsAsSpent":            func() { _ = view.MarkUTXOsAsSpent(ctx, nil, "", nil) },
		"UpdateConsumedBy":            func() { _ = view.UpdateConsumedBy(ctx, nil, "", nil) },
		"UpdateTransactionBEEF":       func() { _ = view.UpdateTransactionBEEF(ctx, nil, nil) },
		"UpdateOutputBlockHeight":     func() { _ = view.UpdateOutputBlockHeight(ctx, nil, "", 0, 0) },
		"InsertAppliedTransaction":    func() { _ = view.InsertAppliedTransaction(ctx, nil) },
		"DoesAppliedTransactionExist": func() { _, _ = view.DoesAppliedTransactionExist(ctx, nil) },
		"UpdateLastInteraction":       func() { _ = view.UpdateLastInteraction(ctx, "", "", 0) },
		"GetLastInteraction":          func() { _, _ = view.GetLastInteraction(ctx, "", "") },
		"FindOutpointsByMerkleState":  func() { _, _ = view.FindOutpointsByMerkleState(ctx, "", 0, 0) },
		"ReconcileMerkleRoot":         func() { _ = view.ReconcileMerkleRoot(ctx, "", 0, nil) },
		"LoadAncillaryBeef":           func() { _ = view.LoadAncillaryBeef(ctx, nil) },
	}
	assertCalls(t, reflect.TypeFor[engine.Storage](), calls, seen, true)
}

// TestDetachedLookup_NotificationsIgnoreCancellation: the five notification
// callbacks must reach the service with a live context and the caller's
// values; Lookup must reach it with the caller's context, cancellation
// included, so a client disconnect still stops a query; the two metadata
// methods pass through.
func TestDetachedLookup_NotificationsIgnoreCancellation(t *testing.T) {
	seen := recorder{}
	meta := &overlay.MetaData{Name: "ls_recording"}
	view := detachedLookup{inner: recordingLookup{seen: seen, meta: meta}}
	ctx := cancelledCtx()
	notifications := map[string]func(){
		"OutputAdmittedByTopic":           func() { _ = view.OutputAdmittedByTopic(ctx, nil) },
		"OutputSpent":                     func() { _ = view.OutputSpent(ctx, nil) },
		"OutputNoLongerRetainedInHistory": func() { _ = view.OutputNoLongerRetainedInHistory(ctx, nil, "") },
		"OutputEvicted":                   func() { _ = view.OutputEvicted(ctx, nil) },
		"OutputBlockHeightUpdated":        func() { _ = view.OutputBlockHeightUpdated(ctx, nil, 0, 0) },
	}
	iface := reflect.TypeFor[engine.LookupService]()
	assertCalls(t, iface, notifications, seen, true, "Lookup", "GetDocumentation", "GetMetaData")
	assertCalls(t, iface, map[string]func(){"Lookup": func() { _, _ = view.Lookup(ctx, nil) }}, seen, false,
		"OutputAdmittedByTopic", "OutputSpent", "OutputNoLongerRetainedInHistory", "OutputEvicted",
		"OutputBlockHeightUpdated", "GetDocumentation", "GetMetaData")
	if got := view.GetDocumentation(); got != "recording lookup" {
		t.Errorf("GetDocumentation = %q", got)
	}
	if got := view.GetMetaData(); got != meta {
		t.Errorf("GetMetaData = %+v, want the service's", got)
	}
}

// TestDetachedLookup_KeepsTheHealthRecord: New registers each service as
// detachedLookup over countingLookup. A notify failure must still propagate
// and be recorded in the health registry, while the service sees a live
// context although the engine's is cancelled.
func TestDetachedLookup_KeepsTheHealthRecord(t *testing.T) {
	reg := health.New()
	seen := recorder{}
	boom := errors.New("kvstore lookup: parse beef: boom")
	view := detachedLookup{inner: countingLookup{LookupService: recordingLookup{seen: seen, err: boom}, reg: reg}}
	err := view.OutputAdmittedByTopic(cancelledCtx(), &engine.OutputAdmittedByTopic{Topic: "tm_kvstore"})
	if !errors.Is(err, boom) {
		t.Fatalf("the notify error did not propagate: %v", err)
	}
	if s := reg.Snapshot(); s.Total != 1 || s.ByTopic["tm_kvstore"].Total != 1 {
		t.Errorf("expected 1 recorded error for tm_kvstore, got %+v", s)
	}
	if got := seen["OutputAdmittedByTopic"]; got.err != nil {
		t.Errorf("the service saw a cancelled context: %v", got.err)
	}
}

// TestNew_EngineSeesOnlyDetachedViews: New must give the engine its storage
// through detachedStorage and every registered lookup service, the SHIP and
// SLAP ones from go-overlay-discovery-services included, through
// detachedLookup over countingLookup.
func TestNew_EngineSeesOnlyDetachedViews(t *testing.T) {
	eng, _ := newTestEngine(t)
	if _, ok := eng.Storage.(detachedStorage); !ok {
		t.Errorf("the engine's storage is %T, want detachedStorage", eng.Storage)
	}
	services := eng.ListLookupServiceProviders()
	for _, name := range []string{ship.Service, slap.Service} {
		if _, ok := services[name]; !ok {
			t.Errorf("%s is not registered", name)
		}
	}
	for name := range services {
		svc, _ := eng.GetLookupService(name)
		view, ok := svc.(detachedLookup)
		if !ok {
			t.Errorf("%s is registered as %T, want detachedLookup", name, svc)
			continue
		}
		if _, ok := view.inner.(countingLookup); !ok {
			t.Errorf("%s: detachedLookup wraps %T, want countingLookup", name, view.inner)
		}
	}
	t.Logf("%d lookup services checked", len(services))
}
