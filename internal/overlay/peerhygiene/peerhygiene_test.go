package peerhygiene

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// fakeClock is a manually-advanced clock for deterministic backoff tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeFacilitator is a controllable inner Facilitator that counts calls.
type fakeFacilitator struct {
	mu     sync.Mutex
	calls  int
	answer *lookup.LookupAnswer
	err    error
}

func (f *fakeFacilitator) Lookup(_ context.Context, _ string, _ *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.answer, f.err
}

func (f *fakeFacilitator) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeFacilitator) setResult(answer *lookup.LookupAnswer, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer, f.err = answer, err
}

const testHost = "https://dead.example"

func newTestFacilitator(inner lookup.Facilitator, clk *fakeClock) *Facilitator {
	return newFacilitatorWithClock(inner, nil, clk.Now)
}

// TestFacilitator_BacksOffAfterRepeatedFailures: once a host crosses the failure
// threshold it is skipped (short-circuited) without hitting the inner HTTP call.
func TestFacilitator_BacksOffAfterRepeatedFailures(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &fakeFacilitator{err: errors.New("404 lookup failed")}
	f := newTestFacilitator(inner, clk)

	for i := 1; i <= 2; i++ {
		if _, err := f.Lookup(context.Background(), testHost, nil); err == nil {
			t.Fatalf("call %d: expected inner error", i)
		}
	}
	if inner.callCount() != 2 {
		t.Fatalf("first 2 calls must hit inner, got %d", inner.callCount())
	}

	_, err := f.Lookup(context.Background(), testHost, nil)
	if !errors.Is(err, ErrHostInBackoff) {
		t.Fatalf("3rd call should be skipped with ErrHostInBackoff, got %v", err)
	}
	if inner.callCount() != 2 {
		t.Fatalf("a backed-off host must NOT hit inner; calls=%d", inner.callCount())
	}
}

// TestFacilitator_RetriesAfterBackoffExpires: when the backoff window elapses the
// host gets exactly one retry.
func TestFacilitator_RetriesAfterBackoffExpires(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &fakeFacilitator{err: errors.New("dead")}
	f := newTestFacilitator(inner, clk)

	f.Lookup(context.Background(), testHost, nil)
	f.Lookup(context.Background(), testHost, nil) // → backed off (1m base)
	if _, err := f.Lookup(context.Background(), testHost, nil); !errors.Is(err, ErrHostInBackoff) {
		t.Fatalf("expected backoff after 2 failures, got %v", err)
	}
	callsBefore := inner.callCount()

	clk.Advance(2 * time.Minute) // past the 1m window
	if _, err := f.Lookup(context.Background(), testHost, nil); errors.Is(err, ErrHostInBackoff) {
		t.Fatal("after backoff expiry the host must be retried, not skipped")
	}
	if inner.callCount() != callsBefore+1 {
		t.Fatalf("expired backoff must allow exactly one retry; calls=%d want %d", inner.callCount(), callsBefore+1)
	}
}

// TestFacilitator_SuccessClearsBackoff: a recovered host is no longer skipped.
func TestFacilitator_SuccessClearsBackoff(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &fakeFacilitator{err: errors.New("dead")}
	f := newTestFacilitator(inner, clk)

	f.Lookup(context.Background(), testHost, nil)
	f.Lookup(context.Background(), testHost, nil) // backed off
	clk.Advance(2 * time.Minute)
	inner.setResult(&lookup.LookupAnswer{}, nil) // host recovers

	if _, err := f.Lookup(context.Background(), testHost, nil); err != nil {
		t.Fatalf("retry after recovery should succeed, got %v", err)
	}
	callsBefore := inner.callCount()
	if _, err := f.Lookup(context.Background(), testHost, nil); errors.Is(err, ErrHostInBackoff) {
		t.Fatal("a recovered host must not be backed off")
	}
	if inner.callCount() != callsBefore+1 {
		t.Fatalf("recovered host must hit inner again; calls=%d", inner.callCount())
	}
}

// TestFacilitator_ContextCanceledNotPenalised: our own cancellation (shutdown)
// must not count against a host.
func TestFacilitator_ContextCanceledNotPenalised(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &fakeFacilitator{err: context.Canceled}
	f := newTestFacilitator(inner, clk)

	for i := 0; i < 5; i++ {
		if _, err := f.Lookup(context.Background(), testHost, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("call %d: expected context.Canceled passthrough, got %v", i, err)
		}
	}
	if inner.callCount() != 5 {
		t.Fatalf("context.Canceled must not back off the host; want 5 inner calls, got %d", inner.callCount())
	}
}

// TestFacilitator_HealthyHostNeverBacksOff: a host that always answers is never skipped.
func TestFacilitator_HealthyHostNeverBacksOff(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &fakeFacilitator{answer: &lookup.LookupAnswer{}}
	f := newTestFacilitator(inner, clk)

	for i := 0; i < 10; i++ {
		if _, err := f.Lookup(context.Background(), testHost, nil); err != nil {
			t.Fatalf("healthy host call %d errored: %v", i, err)
		}
	}
	if inner.callCount() != 10 {
		t.Fatalf("healthy host must always hit inner; got %d", inner.callCount())
	}
}

// TestTracker_BackoffEscalatesPerWindowAndCaps locks the schedule: a fresh
// failure crosses the threshold to the base window, failures WITHIN an active
// window don't escalate, and only post-expiry failures double it — up to the cap.
func TestTracker_BackoffEscalatesPerWindowAndCaps(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	tr := newTracker(clk.Now)

	if d := tr.recordFailure("h"); !d.IsZero() {
		t.Fatalf("1st failure (below threshold) must not back off, got %v", d)
	}
	if got := tr.recordFailure("h").Sub(clk.Now()); got != time.Minute {
		t.Fatalf("first backoff should be 1m, got %v", got)
	}
	// Failures within the active 1m window must NOT escalate.
	for i := 0; i < 5; i++ {
		if got := tr.recordFailure("h").Sub(clk.Now()); got != time.Minute {
			t.Fatalf("within-window failure must not escalate; got %v", got)
		}
	}
	// Past the window, a fresh failure doubles it.
	clk.Advance(90 * time.Second)
	if got := tr.recordFailure("h").Sub(clk.Now()); got != 2*time.Minute {
		t.Fatalf("second window should be 2m, got %v", got)
	}
	// Keep failing across windows → caps at 1h.
	var last time.Duration
	for i := 0; i < 12; i++ {
		clk.Advance(2 * time.Hour) // always past the current window
		last = tr.recordFailure("h").Sub(clk.Now())
	}
	if last != time.Hour {
		t.Fatalf("backoff should cap at 1h, got %v", last)
	}
}

// TestFacilitator_BurstFailuresDoNotOverEscalate is the regression for Codex's
// residual: many CONCURRENT per-topic failures to one dead host in a single sync
// must not rocket it to the 1h cap. The burst collapses to the base window, so a
// host that recovers next round isn't stuck for hours.
func TestFacilitator_BurstFailuresDoNotOverEscalate(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	inner := &fakeFacilitator{err: errors.New("dead tracker")}
	f := newTestFacilitator(inner, clk)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ { // 20 concurrent "topic" queries to the same host
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.Lookup(context.Background(), testHost, nil)
		}()
	}
	wg.Wait()

	if !f.tracker.inBackoff(testHost) {
		t.Fatal("a fully-dead host must be backed off after the burst")
	}
	// Past the base 1m window but far short of any escalated window: clearing
	// here proves the burst only reached the first level, not the cap.
	clk.Advance(90 * time.Second)
	if f.tracker.inBackoff(testHost) {
		t.Fatal("burst over-escalated: still backed off after 90s (expected base 1m)")
	}
}

// TestResolver_SLAPTrackerWiring confirms the provider mirrors the engine's
// SLAP-tracker semantics (set replaces; empty is a no-op).
func TestResolver_SLAPTrackerWiring(t *testing.T) {
	r := NewResolver(overlay.NetworkMainnet, nil)
	r.SetSLAPTrackers([]string{"https://a.example", "https://b.example"})
	if got := r.SLAPTrackers(); len(got) != 2 || got[0] != "https://a.example" {
		t.Fatalf("SLAP trackers not wired: %v", got)
	}
	r.SetSLAPTrackers(nil)
	if got := r.SLAPTrackers(); len(got) != 2 {
		t.Fatalf("empty SetSLAPTrackers must be a no-op; got %v", got)
	}
}
