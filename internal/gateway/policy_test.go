package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestPolicy builds a Policy over a sites file written with body and a
// Resolver backed by fake. apiHost is irrelevant to Policy's own rules
// (that overlap is Allowlist's and internal/config's concern — see
// TestAllowlist_APIHostDomainEntryIgnoredOnReload and
// internal/config/gateway_test.go), so it's left empty here.
func newTestPolicy(t *testing.T, body string, fake *fakeTXTLookup) (*Policy, *Allowlist, *Resolver) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway-sites.conf")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	allow := NewAllowlist(path, "", slog.Default())
	clock := time.Now()
	r := newTestResolver(fake, &clock)
	return NewPolicy(allow, r), allow, r
}

func TestPolicy_DomainEntry(t *testing.T) {
	origin := testOutpoint(20, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain example.org\n", fake)

	got, ok := p.Allowed(context.Background(), "example.org")
	if !ok || got != origin {
		t.Fatalf("Allowed = (%q, %v), want (%q, true)", got, ok, origin)
	}
}

// TestPolicy_DomainEntryCaseInsensitiveHost confirms that a sites-file
// domain entry matches a Host differing
// only in case from the configured domain must still match.
func TestPolicy_DomainEntryCaseInsensitiveHost(t *testing.T) {
	origin := testOutpoint(27, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain example.org\n", fake)

	got, ok := p.Allowed(context.Background(), "EXAMPLE.ORG")
	if !ok || got != origin {
		t.Fatalf("Allowed(EXAMPLE.ORG) = (%q, %v), want (%q, true)", got, ok, origin)
	}
}

// TestPolicy_DomainEntryTrailingDotHost confirms that a sites-file domain
// entry matches a Host with one trailing
// dot must still match a domain entry configured without one.
func TestPolicy_DomainEntryTrailingDotHost(t *testing.T) {
	origin := testOutpoint(28, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain example.org\n", fake)

	got, ok := p.Allowed(context.Background(), "example.org.")
	if !ok || got != origin {
		t.Fatalf("Allowed(example.org.) = (%q, %v), want (%q, true)", got, ok, origin)
	}
}

func TestPolicy_OriginEntry(t *testing.T) {
	origin := testOutpoint(21, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "origin "+origin+"\n", fake)

	// No domain entry for "other.org", but its TXT resolves to a listed origin.
	got, ok := p.Allowed(context.Background(), "other.org")
	if !ok || got != origin {
		t.Fatalf("Allowed = (%q, %v), want (%q, true)", got, ok, origin)
	}
}

func TestPolicy_BothDomainAndOrigin(t *testing.T) {
	origin := testOutpoint(22, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	body := "domain example.org\norigin " + origin + "\n"
	p, _, _ := newTestPolicy(t, body, fake)

	got, ok := p.Allowed(context.Background(), "example.org")
	if !ok || got != origin {
		t.Fatalf("Allowed = (%q, %v), want (%q, true)", got, ok, origin)
	}
}

func TestPolicy_TXTDoesNotMatchAnyOriginEntry(t *testing.T) {
	listedOrigin := testOutpoint(23, 0)
	resolvedOrigin := testOutpoint(23, 1) // a different, unlisted origin
	fake := &fakeTXTLookup{records: []string{"ordfs=" + resolvedOrigin}}
	p, _, _ := newTestPolicy(t, "origin "+listedOrigin+"\n", fake)

	_, ok := p.Allowed(context.Background(), "other.org")
	if ok {
		t.Fatal("expected refusal: TXT resolves to an origin that isn't on the list")
	}
}

func TestPolicy_DomainEntryWithNoValidTXT(t *testing.T) {
	// A listed domain with no valid TXT gets a 404.
	fake := &fakeTXTLookup{records: nil} // no TXT record at all
	p, _, _ := newTestPolicy(t, "domain example.org\n", fake)

	_, ok := p.Allowed(context.Background(), "example.org")
	if ok {
		t.Fatal("expected refusal: domain is listed but has no valid TXT")
	}
}

func TestPolicy_NoDomainNoOriginEntriesSkipsLookupEntirely(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(24, 0)}}
	// Sites file has nothing at all.
	p, _, _ := newTestPolicy(t, "", fake)

	_, ok := p.Allowed(context.Background(), "random.example.org")
	if ok {
		t.Fatal("expected refusal when the sites file has no entries at all")
	}
	if fake.callCount() != 0 {
		t.Fatalf("expected no TXT lookup at all when there's nothing to match against, got %d calls", fake.callCount())
	}
}

// TestPolicy_FloodGuardBlocksSpeculativeLookup exhausts the flood guard's
// burst with distinct speculative (no-domain-entry) hosts — each a
// genuine cache miss, so each burns one guard token and one real DNS call
// — then confirms one more distinct host is refused with no new DNS call
// at all; the guard still gates a genuine cache miss exactly as
// before; what changed is that it no longer ALSO gates a cache hit — see
// TestHostile_FloodGuardThrottlesCachedOriginTraffic).
func TestPolicy_FloodGuardBlocksSpeculativeLookup(t *testing.T) {
	listedOrigin := testOutpoint(25, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + listedOrigin}}
	p, _, _ := newTestPolicy(t, "origin "+listedOrigin+"\n", fake)

	for i := 0; i < floodGuardBurst; i++ {
		p.Allowed(context.Background(), fmt.Sprintf("burst-host-%d.example.org", i))
	}
	if fake.callCount() != floodGuardBurst {
		t.Fatalf("expected %d real lookups to exhaust the burst, got %d", floodGuardBurst, fake.callCount())
	}

	_, ok := p.Allowed(context.Background(), "one-more-host.example.org")
	if ok {
		t.Fatal("expected refusal once the flood guard's burst is exhausted")
	}
	if fake.callCount() != floodGuardBurst {
		t.Fatalf("expected the flood guard to block the lookup itself (no new DNS call), got %d calls", fake.callCount())
	}
}

// TestHostile_FloodGuardThrottlesCachedOriginTraffic makes the review's
// permanent regression: a cached, allowed, origin-only host (no
// domain entry — its only path to being allowed is its TXT resolving to a
// listed "origin" entry) must never be refused by the flood guard, no
// matter how exhausted the guard's global burst is, because a cache hit
// never reaches the guard at all because the check follows Resolver's
// own cache lookup, inside Lookup, never ahead of it in Policy.Allowed as
// before). Before the fix, every one of these calls re-consulted the
// guard regardless of the cache, so exhausting the burst on unrelated
// traffic — as this test does first — started refusing the cached host
// too (the review's repro: 100 calls, 81 refused).
func TestHostile_FloodGuardThrottlesCachedOriginTraffic(t *testing.T) {
	origin := testOutpoint(26, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "origin "+origin+"\n", fake)

	host := "cached.example.org"
	if _, ok := p.Allowed(context.Background(), host); !ok {
		t.Fatal("expected the priming lookup to succeed")
	}

	// Exhaust the flood guard's burst on OTHER (distinct, uncached) hosts.
	for i := 0; i < floodGuardBurst+5; i++ {
		p.Allowed(context.Background(), fmt.Sprintf("unrelated-%d.example.org", i))
	}
	callsAfterExhaustion := fake.callCount()

	const n = 25
	for i := 0; i < n; i++ {
		_, ok := p.Allowed(context.Background(), host)
		if !ok {
			t.Fatalf("call %d: expected a cached, allowed, origin-only host to never be refused by the flood guard", i)
		}
	}
	if fake.callCount() != callsAfterExhaustion {
		t.Fatalf("expected no new DNS calls for the cached host, got %d (was %d right after exhausting the burst)",
			fake.callCount(), callsAfterExhaustion)
	}
}
