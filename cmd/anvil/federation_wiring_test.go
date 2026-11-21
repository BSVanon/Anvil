package main

import (
	"io"
	"log/slog"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// wireV3Federation itself.
//
// federation_loops_test.go's tests exercise buildSyncConfiguration/
// resolveFederationTrackers directly; none of them call wireV3Federation, so
// a bug in its own gating (the actual review finding: the public_url == ""
// early return ran before named_peers was ever read) went uncaught. These
// three cover the fix spec's required scenarios (a)/(b)/(c) through
// wireV3Federation itself.
//
// All three pass nil for shipStore/slapStore/anvilStore/nodeWallet: in
// every scenario below, a correct implementation never dereferences them
// (scenario (a) returns before reading them at all; scenarios (b)/(c) are
// closedNetwork, where the Advertiser -- the only thing that touches them
// -- must never be constructed). A regression that still constructs the
// Advertiser under named_peers would nil-pointer panic on nodeWallet.Wallet()
// before this test's assertion even runs, which is a stronger failure
// signal than the explicit v3Eng.Advertiser == nil check these also make.
//
// Split from federation_loops_test.go to keep that file under the project's
// line-count cap; newSyncConfigTestEngine is defined there and shared here
// since both files are package main.
//
// wireV3Federation now returns a cancel func for whatever background
// loop(s) it started (previously on context.Background(), with no way for
// any caller to stop them -- including the scenario (b)/(c) calls below,
// each of which starts the GASP sync loop). Every call below routes its
// returned func through t.Cleanup so this file leaves nothing running past
// its own tests, same as a correctly behaving caller must.

// newFederationTestLogger returns a discard logger -- these tests assert on
// engine state, not log output (federation_loops_test.go's other tests
// already cover the log-content cases).
func newFederationTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestWireV3Federation_BothUnsetMatchesOriginalBehavior is the mutation
// check for fix-spec scenario (a): with named_peers and public_url both
// unset, wireV3Federation must return before touching the engine at all --
// identical to e63349f, before named_peers existed.
func TestWireV3Federation_BothUnsetMatchesOriginalBehavior(t *testing.T) {
	eng := newSyncConfigTestEngine([]string{"tm_ship", "tm_slap", "tm_uhrp"}, nil, nil)
	// engine.NewEngine always fills a non-nil default LookupResolver itself
	// (engine.go: "if e.LookupResolver == nil { e.LookupResolver =
	// NewLookupResolver() }"), so "wireV3Federation touched nothing" must be
	// proved by reference equality to this pre-call value, not by nil.
	originalResolver := eng.LookupResolver
	cfg := &config.Config{}
	cfg.Overlay.EnableGASPSync = true
	// cfg.Node.PublicURL and cfg.Overlay.NamedPeers both left unset.

	t.Cleanup(wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger()))

	if eng.Advertiser != nil {
		t.Errorf("Advertiser = %v, want nil (public_url unset, named_peers unset)", eng.Advertiser)
	}
	if eng.LookupResolver != originalResolver {
		t.Errorf("LookupResolver changed from its engine.NewEngine default, want untouched (wireV3Federation must return before wiring anything)")
	}
	if len(eng.SyncConfiguration) != 0 {
		t.Errorf("SyncConfiguration = %+v, want empty (engine.NewEngine's untouched default)", eng.SyncConfiguration)
	}
}

// TestWireV3Federation_NamedPeersWithoutPublicURL is the mutation check for
// fix-spec scenario (b), the brick's own motivating case ("peer only with
// named nodes, advertise nothing"): named_peers set, public_url unset. GASP
// sync must wire to the named peers; the advertiser must never be
// constructed.
func TestWireV3Federation_NamedPeersWithoutPublicURL(t *testing.T) {
	eng := newSyncConfigTestEngine([]string{"tm_ship", "tm_slap", "tm_uhrp"}, nil, nil)
	cfg := &config.Config{}
	cfg.Overlay.EnableGASPSync = true
	// Loopback ports nothing listens on, not DNS names: this starts the
	// real GASP sync loop (asserted below via SyncConfiguration), whose
	// first attempt must fail with an immediate local connection refusal
	// rather than depend on, or wait on, outbound DNS/network access --
	// relevant now that this loop's goroutine is a correctness property
	// CancelStopsBackgroundLoops below measures across tests in this file.
	cfg.Overlay.NamedPeers = []string{"http://127.0.0.1:1", "http://127.0.0.1:2"}
	// cfg.Node.PublicURL left unset -- this is the review's exact finding:
	// wireV3Federation used to return here before ever reading NamedPeers.

	t.Cleanup(wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger()))

	if eng.Advertiser != nil {
		t.Errorf("Advertiser = %v, want nil (named_peers set -- advertiser must never run under it)", eng.Advertiser)
	}
	if eng.LookupResolver == nil {
		t.Error("LookupResolver = nil, want wired (named_peers must still enable GASP sync with no public_url)")
	}
	wantPeers := cfg.Overlay.NamedPeers
	if !reflect.DeepEqual(eng.SHIPTrackers, wantPeers) || !reflect.DeepEqual(eng.SLAPTrackers, wantPeers) {
		t.Errorf("SHIPTrackers=%v SLAPTrackers=%v, want both %v", eng.SHIPTrackers, eng.SLAPTrackers, wantPeers)
	}
	if len(eng.SyncConfiguration) != 3 {
		t.Fatalf("SyncConfiguration has %d topics, want 3", len(eng.SyncConfiguration))
	}
	for _, name := range []string{"tm_ship", "tm_slap", "tm_uhrp"} {
		got := eng.SyncConfiguration[name]
		if got.Type != engine.SyncConfigurationPeers || !reflect.DeepEqual(got.Peers, wantPeers) {
			t.Errorf("topic %q = %+v, want {SyncConfigurationPeers, %v}", name, got, wantPeers)
		}
	}
}

// TestWireV3Federation_NamedPeersWithPublicURLStillNoAdvertiser is the
// mutation check for fix-spec scenario (c): named_peers AND public_url both
// set. The advertiser must still never be constructed -- public_url being
// set must not re-enable it, because any advert it submits reaches
// engine.Broadcaster/ARC unconditionally (main.go wires Broadcaster
// regardless of named_peers) and would permanently link this node's
// identity on the public chain, the exact outcome closed-network mode
// exists to prevent.
func TestWireV3Federation_NamedPeersWithPublicURLStillNoAdvertiser(t *testing.T) {
	eng := newSyncConfigTestEngine([]string{"tm_ship", "tm_slap", "tm_uhrp"}, nil, nil)
	cfg := &config.Config{}
	cfg.Overlay.EnableGASPSync = true
	// See the loopback-not-DNS comment in NamedPeersWithoutPublicURL above;
	// PublicURL below is never dialed on this path (no Advertiser), so it
	// keeps its original value.
	cfg.Overlay.NamedPeers = []string{"http://127.0.0.1:1"}
	cfg.Node.PublicURL = "https://this-node.example" // set -- must not matter

	t.Cleanup(wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger()))

	if eng.Advertiser != nil {
		t.Errorf("Advertiser = %v, want nil even with public_url set (named_peers wins; see advertiser.go NewAdvertiser / main.go's unconditional Broadcaster wiring)", eng.Advertiser)
	}
	if eng.LookupResolver == nil {
		t.Error("LookupResolver = nil, want wired")
	}
	wantPeers := cfg.Overlay.NamedPeers
	for _, name := range []string{"tm_ship", "tm_slap", "tm_uhrp"} {
		got := eng.SyncConfiguration[name]
		if got.Type != engine.SyncConfigurationPeers || !reflect.DeepEqual(got.Peers, wantPeers) {
			t.Errorf("topic %q = %+v, want {SyncConfigurationPeers, %v}", name, got, wantPeers)
		}
	}
}

// TestWireV3Federation_NamedPeersSanitizesBlankEntries is the mutation check
// for named_peers: blank/whitespace-only entries must not count as
// "named_peers is set", mirroring allowed_peers' own sanitization
// (internal/gossip/allowlist.go's newPeerAllowlist).
func TestWireV3Federation_NamedPeersSanitizesBlankEntries(t *testing.T) {
	eng := newSyncConfigTestEngine([]string{"tm_uhrp"}, nil, nil)
	originalResolver := eng.LookupResolver // see BothUnsetMatchesOriginalBehavior
	cfg := &config.Config{}
	cfg.Overlay.EnableGASPSync = true
	cfg.Overlay.NamedPeers = []string{"  ", "\t", ""}
	// public_url also unset: if sanitization didn't strip these down to
	// empty, wiring would proceed as closedNetwork; if it did, this must
	// behave exactly like TestWireV3Federation_BothUnsetMatchesOriginalBehavior.

	t.Cleanup(wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger()))

	if eng.LookupResolver != originalResolver {
		t.Error("LookupResolver changed from its engine.NewEngine default, want untouched -- blank-only named_peers must sanitize to unset")
	}
	if len(eng.SyncConfiguration) != 0 {
		t.Errorf("SyncConfiguration = %+v, want empty -- blank-only named_peers must sanitize to unset", eng.SyncConfiguration)
	}
}

// TestWireV3Federation_CancelStopsBackgroundLoops is the leak-regression
// test for the cancelable-context fix: wireV3Federation's background
// loops (runSyncAdvertisements, runGASPSync) used to run on
// context.Background(), which nothing could ever stop -- including every
// scenario-(b)/(c) call above, each of which starts the GASP sync loop and,
// before this fix, would leak it for the rest of the test binary's life.
// Proves the returned cancel func actually stops the loop it started, via
// a goroutine count that rises once wired and settles back down once
// cancelled, not just that calling it doesn't panic.
//
// Uses named_peers pointed at a loopback port nothing listens on
// (127.0.0.1:1, a reserved port) rather than a DNS name: GASP sync's first
// attempt then fails with an immediate local connection refusal, with no
// DNS lookup and no dependency on outbound network access, so this test's
// timing reflects only the fix under test. Scenario (b) (named_peers set,
// public_url unset) is used so nodeWallet can stay nil -- no Advertiser is
// constructed, and the only loop wireV3Federation starts is runGASPSync.
//
// Establishes its baseline via settledGoroutineCount rather than a bare
// runtime.NumGoroutine() call: each scenario-(b)/(c) test above starts its
// own GASP sync goroutine with `go`, without waiting for its first pass to
// finish, so that goroutine can still be in flight when its test function
// returns and this one starts -- settling first absorbs that instead of
// racing it.
func TestWireV3Federation_CancelStopsBackgroundLoops(t *testing.T) {
	eng := newSyncConfigTestEngine([]string{"tm_uhrp"}, nil, nil)
	cfg := &config.Config{}
	cfg.Overlay.EnableGASPSync = true
	cfg.Overlay.NamedPeers = []string{"http://127.0.0.1:1"}

	before := settledGoroutineCount(t, 3*time.Second)

	cancel := wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger())

	goroutineCountExceeds(t, before, 5, 2*time.Second)

	cancel()

	goroutineCountSettlesBelow(t, before, 5, 5*time.Second)
}

// settledGoroutineCount polls runtime.NumGoroutine() until it reads the
// same value for consecutiveHits samples in a row, returning that value,
// or fails the test once timeout elapses. See the doc comment above on
// why CancelStopsBackgroundLoops needs this rather than a bare call.
func settledGoroutineCount(t *testing.T, timeout time.Duration) int {
	t.Helper()
	const sampleInterval = 20 * time.Millisecond
	const consecutiveHits = 5
	deadline := time.Now().Add(timeout)
	hits := 0
	last := -1
	for time.Now().Before(deadline) {
		cur := runtime.NumGoroutine()
		if cur == last {
			hits++
			if hits >= consecutiveHits {
				return cur
			}
		} else {
			hits = 0
		}
		last = cur
		time.Sleep(sampleInterval)
	}
	t.Fatalf("goroutine count did not settle within %s; last seen %d", timeout, last)
	return -1
}

// goroutineCountExceeds polls runtime.NumGoroutine() until it has read a
// value above floor for consecutiveHits samples in a row, or fails the
// test once timeout elapses. A single matching sample is not enough: the
// scheduler can delay a just-started goroutine, so one early sample could
// win by coincidence rather than because the goroutine under test is
// actually running and staying running.
func goroutineCountExceeds(t *testing.T, floor, consecutiveHits int, timeout time.Duration) {
	t.Helper()
	const sampleInterval = 20 * time.Millisecond
	deadline := time.Now().Add(timeout)
	hits := 0
	last := -1
	for time.Now().Before(deadline) {
		last = runtime.NumGoroutine()
		if last > floor {
			hits++
			if hits >= consecutiveHits {
				return
			}
		} else {
			hits = 0
		}
		time.Sleep(sampleInterval)
	}
	t.Fatalf("NumGoroutine() never exceeded %d for %d consecutive samples within %s; last seen %d", floor, consecutiveHits, timeout, last)
}

// goroutineCountSettlesBelow polls runtime.NumGoroutine() until it has
// read a value at or below ceiling for consecutiveHits samples in a row,
// or fails the test once timeout elapses. Requiring several consecutive
// matching samples, rather than the first one, proves the count has
// actually settled rather than been caught in a transient dip before a
// goroutine that is still running gets rescheduled -- the same hazard
// v3engine's lingering-refusal test guards against with the same pattern.
func goroutineCountSettlesBelow(t *testing.T, ceiling, consecutiveHits int, timeout time.Duration) {
	t.Helper()
	const sampleInterval = 20 * time.Millisecond
	deadline := time.Now().Add(timeout)
	hits := 0
	last := -1
	for time.Now().Before(deadline) {
		last = runtime.NumGoroutine()
		if last <= ceiling {
			hits++
			if hits >= consecutiveHits {
				return
			}
		} else {
			hits = 0
		}
		time.Sleep(sampleInterval)
	}
	t.Fatalf("NumGoroutine() did not settle at <=%d for %d consecutive samples within %s; last seen %d", ceiling, consecutiveHits, timeout, last)
}
