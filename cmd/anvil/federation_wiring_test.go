package main

import (
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// wireV3Federation itself (B5 fix pass, review BLOCKER 1).
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

	wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger())

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
	cfg.Overlay.NamedPeers = []string{"https://named-a.example", "https://named-b.example"}
	// cfg.Node.PublicURL left unset -- this is the review's exact finding:
	// wireV3Federation used to return here before ever reading NamedPeers.

	wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger())

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
	cfg.Overlay.NamedPeers = []string{"https://named-a.example"}
	cfg.Node.PublicURL = "https://this-node.example" // set -- must not matter

	wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger())

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
// for the named_peers nit: blank/whitespace-only entries must not count as
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

	wireV3Federation(cfg, eng, nil, nil, nil, nil, nil, newFederationTestLogger())

	if eng.LookupResolver != originalResolver {
		t.Error("LookupResolver changed from its engine.NewEngine default, want untouched -- blank-only named_peers must sanitize to unset")
	}
	if len(eng.SyncConfiguration) != 0 {
		t.Errorf("SyncConfiguration = %+v, want empty -- blank-only named_peers must sanitize to unset", eng.SyncConfiguration)
	}
}
