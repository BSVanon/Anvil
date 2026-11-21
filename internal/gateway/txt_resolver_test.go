package gateway

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTXTLookup is a controllable txtLookuper for deterministic Resolver
// tests: no real DNS, no real sleeping.
type fakeTXTLookup struct {
	mu      sync.Mutex
	calls   int
	records []string
	err     error
	block   chan struct{} // if non-nil, LookupTXT waits for this to close
}

func (f *fakeTXTLookup) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.records, nil
}

func (f *fakeTXTLookup) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newTestResolver builds a Resolver with a fake lookuper and a controllable
// clock, bypassing NewResolver's hardcoded net.DefaultResolver.
func newTestResolver(fake *fakeTXTLookup, clock *time.Time) *Resolver {
	r := NewResolver(ResolverConfig{
		PositiveTTL: 5 * time.Minute,
		NegativeTTL: time.Minute,
		StaleGrace:  24 * time.Hour,
	})
	r.lookup = fake
	r.now = func() time.Time { return *clock }
	return r
}

func TestResolver_PositiveTTL(t *testing.T) {
	origin := testOutpoint(1, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	clock := time.Now()
	r := newTestResolver(fake, &clock)

	got, ok := r.Lookup(context.Background(), "example.org", false)
	if !ok || got != origin {
		t.Fatalf("first lookup = (%q, %v), want (%q, true)", got, ok, origin)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected 1 real lookup, got %d", fake.callCount())
	}

	// Within TTL: cached, no new lookup.
	clock = clock.Add(4 * time.Minute)
	got, ok = r.Lookup(context.Background(), "example.org", false)
	if !ok || got != origin {
		t.Fatalf("cached lookup = (%q, %v), want (%q, true)", got, ok, origin)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected cache hit (still 1 real lookup), got %d", fake.callCount())
	}

	// Past TTL: a fresh lookup happens.
	clock = clock.Add(2 * time.Minute) // total 6m > 5m TTL
	_, _ = r.Lookup(context.Background(), "example.org", false)
	if fake.callCount() != 2 {
		t.Fatalf("expected a fresh lookup after TTL expiry, got %d calls", fake.callCount())
	}
}

func TestResolver_NegativeEntries(t *testing.T) {
	fake := &fakeTXTLookup{err: &net.DNSError{IsNotFound: true}}
	clock := time.Now()
	r := newTestResolver(fake, &clock)

	_, ok := r.Lookup(context.Background(), "nope.example.org", false)
	if ok {
		t.Fatal("expected no mapping for a definitive NXDOMAIN-style answer")
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected 1 real lookup, got %d", fake.callCount())
	}

	// Within the negative TTL (1m default): still cached, no new lookup.
	clock = clock.Add(30 * time.Second)
	_, ok = r.Lookup(context.Background(), "nope.example.org", false)
	if ok {
		t.Fatal("expected cached negative answer")
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected cache hit, got %d calls", fake.callCount())
	}

	// Past the negative TTL: a fresh lookup happens.
	clock = clock.Add(time.Minute) // total 90s > 60s TTL
	_, _ = r.Lookup(context.Background(), "nope.example.org", false)
	if fake.callCount() != 2 {
		t.Fatalf("expected a fresh lookup after negative TTL expiry, got %d calls", fake.callCount())
	}
}

func TestResolver_StaleGraceOnResolverFailure(t *testing.T) {
	origin := testOutpoint(2, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	clock := time.Now()
	r := newTestResolver(fake, &clock)
	r.staleGrace = time.Hour

	// Establish a good answer.
	got, ok := r.Lookup(context.Background(), "flaky.example.org", false)
	if !ok || got != origin {
		t.Fatalf("expected an initial good answer, got (%q, %v)", got, ok)
	}

	// Expire the cache, then make the resolver fail with a GENUINE error
	// (not a definitive "no such record") — within StaleGrace, the last
	// good answer must still be served.
	clock = clock.Add(6 * time.Minute) // past the 5m positive TTL
	fake.err = &net.DNSError{IsTimeout: true}
	got, ok = r.Lookup(context.Background(), "flaky.example.org", false)
	if !ok || got != origin {
		t.Fatalf("expected stale-grace fallback to the last good answer, got (%q, %v)", got, ok)
	}
	if r.stats.TXTStale.Load() != 1 {
		t.Fatalf("expected gateway_txt_stale_served=1, got %d", r.stats.TXTStale.Load())
	}

	// Past StaleGrace (measured from the original good answer): no mapping.
	clock = clock.Add(2 * time.Hour)
	_, ok = r.Lookup(context.Background(), "flaky.example.org", false)
	if ok {
		t.Fatal("expected stale grace to be exhausted")
	}
}

func TestResolver_DefinitiveNegativeNotMaskedByStaleGrace(t *testing.T) {
	// A LEGITIMATE "no such record" answer (the owner changed or removed
	// their TXT) must not be masked by a previously-good answer — only a
	// genuine resolver error gets the stale-grace fallback.
	origin := testOutpoint(3, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	clock := time.Now()
	r := newTestResolver(fake, &clock)

	if _, ok := r.Lookup(context.Background(), "changed.example.org", false); !ok {
		t.Fatal("expected an initial good answer")
	}

	clock = clock.Add(6 * time.Minute)
	fake.records = nil
	fake.err = &net.DNSError{IsNotFound: true}
	_, ok := r.Lookup(context.Background(), "changed.example.org", false)
	if ok {
		t.Fatal("a definitive negative answer must not fall back to the stale good answer")
	}
}

func TestResolver_Singleflight(t *testing.T) {
	origin := testOutpoint(4, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}, block: make(chan struct{})}
	clock := time.Now()
	r := newTestResolver(fake, &clock)

	const n = 20
	var wg sync.WaitGroup
	var successes atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := r.Lookup(context.Background(), "popular.example.org", false); ok {
				successes.Add(1)
			}
		}()
	}

	// Give the goroutines a moment to pile up inside singleflight, then
	// release the one real lookup they all share.
	time.Sleep(50 * time.Millisecond)
	close(fake.block)
	wg.Wait()

	if successes.Load() != n {
		t.Fatalf("expected all %d callers to succeed, got %d", n, successes.Load())
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected exactly 1 real lookup shared by %d concurrent callers, got %d", n, fake.callCount())
	}
}

// TestResolver_FloodGuardThrottlesDistinctUncachedHosts replaces the old
// TestResolver_FloodGuard verifies behavior after AllowSpeculative was removed: the
// flood guard is consulted inside Lookup itself, only on a genuine cache
// miss for a speculative (no-domain-entry) host. A flood of distinct,
// never-before-seen hosts is still capped at the guard's burst — counted
// here by real DNS calls rather than elapsed time.
// them" — and, separately, the guard still refills after elapsed time.
func TestResolver_FloodGuardThrottlesDistinctUncachedHosts(t *testing.T) {
	fake := &fakeTXTLookup{err: &net.DNSError{IsNotFound: true}}
	clock := time.Now()
	r := newTestResolver(fake, &clock)
	r.flood.now = func() time.Time { return clock }

	const extra = 10
	for i := 0; i < floodGuardBurst+extra; i++ {
		r.Lookup(context.Background(), fmt.Sprintf("distinct-%d.example.org", i), true)
	}
	if fake.callCount() != floodGuardBurst {
		t.Fatalf("expected real DNS calls capped at the burst (%d) across %d distinct hosts, got %d",
			floodGuardBurst, floodGuardBurst+extra, fake.callCount())
	}

	// After enough elapsed time to refill at least one token, a further
	// distinct host reaches a real lookup again.
	clock = clock.Add(time.Second)
	r.Lookup(context.Background(), "refilled-after-wait.example.org", true)
	if fake.callCount() != floodGuardBurst+1 {
		t.Fatalf("expected the flood guard to refill after 1s at %d/s, got %d calls", floodGuardRate, fake.callCount())
	}
}
