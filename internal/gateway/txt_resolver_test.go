package gateway

import (
	"context"
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

	got, ok := r.Lookup(context.Background(), "example.org")
	if !ok || got != origin {
		t.Fatalf("first lookup = (%q, %v), want (%q, true)", got, ok, origin)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected 1 real lookup, got %d", fake.callCount())
	}

	// Within TTL: cached, no new lookup.
	clock = clock.Add(4 * time.Minute)
	got, ok = r.Lookup(context.Background(), "example.org")
	if !ok || got != origin {
		t.Fatalf("cached lookup = (%q, %v), want (%q, true)", got, ok, origin)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected cache hit (still 1 real lookup), got %d", fake.callCount())
	}

	// Past TTL: a fresh lookup happens.
	clock = clock.Add(2 * time.Minute) // total 6m > 5m TTL
	_, _ = r.Lookup(context.Background(), "example.org")
	if fake.callCount() != 2 {
		t.Fatalf("expected a fresh lookup after TTL expiry, got %d calls", fake.callCount())
	}
}

func TestResolver_NegativeEntries(t *testing.T) {
	fake := &fakeTXTLookup{err: &net.DNSError{IsNotFound: true}}
	clock := time.Now()
	r := newTestResolver(fake, &clock)

	_, ok := r.Lookup(context.Background(), "nope.example.org")
	if ok {
		t.Fatal("expected no mapping for a definitive NXDOMAIN-style answer")
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected 1 real lookup, got %d", fake.callCount())
	}

	// Within the negative TTL (1m default): still cached, no new lookup.
	clock = clock.Add(30 * time.Second)
	_, ok = r.Lookup(context.Background(), "nope.example.org")
	if ok {
		t.Fatal("expected cached negative answer")
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected cache hit, got %d calls", fake.callCount())
	}

	// Past the negative TTL: a fresh lookup happens.
	clock = clock.Add(time.Minute) // total 90s > 60s TTL
	_, _ = r.Lookup(context.Background(), "nope.example.org")
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
	got, ok := r.Lookup(context.Background(), "flaky.example.org")
	if !ok || got != origin {
		t.Fatalf("expected an initial good answer, got (%q, %v)", got, ok)
	}

	// Expire the cache, then make the resolver fail with a GENUINE error
	// (not a definitive "no such record") — within StaleGrace, the last
	// good answer must still be served.
	clock = clock.Add(6 * time.Minute) // past the 5m positive TTL
	fake.err = &net.DNSError{IsTimeout: true}
	got, ok = r.Lookup(context.Background(), "flaky.example.org")
	if !ok || got != origin {
		t.Fatalf("expected stale-grace fallback to the last good answer, got (%q, %v)", got, ok)
	}
	if r.stats.TXTStale.Load() != 1 {
		t.Fatalf("expected gateway_txt_stale_served=1, got %d", r.stats.TXTStale.Load())
	}

	// Past StaleGrace (measured from the original good answer): no mapping.
	clock = clock.Add(2 * time.Hour)
	_, ok = r.Lookup(context.Background(), "flaky.example.org")
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

	if _, ok := r.Lookup(context.Background(), "changed.example.org"); !ok {
		t.Fatal("expected an initial good answer")
	}

	clock = clock.Add(6 * time.Minute)
	fake.records = nil
	fake.err = &net.DNSError{IsNotFound: true}
	_, ok := r.Lookup(context.Background(), "changed.example.org")
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
			if _, ok := r.Lookup(context.Background(), "popular.example.org"); ok {
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

func TestResolver_FloodGuard(t *testing.T) {
	r := NewResolver(ResolverConfig{})
	clock := time.Now()
	r.flood.now = func() time.Time { return clock }

	allowed := 0
	for i := 0; i < floodGuardBurst+5; i++ {
		if r.AllowSpeculative() {
			allowed++
		}
	}
	if allowed != floodGuardBurst {
		t.Fatalf("expected exactly burst (%d) requests allowed, got %d", floodGuardBurst, allowed)
	}

	// After the burst is exhausted, a further call this instant is refused.
	if r.AllowSpeculative() {
		t.Fatal("expected the flood guard to refuse once its burst is exhausted")
	}

	// After enough elapsed time to refill at least one token, it allows again.
	clock = clock.Add(time.Second)
	if !r.AllowSpeculative() {
		t.Fatal("expected the flood guard to refill after 1s at 5/s")
	}
}
