package gateway

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestPolicy builds a Policy over a sites file written with body and a
// Resolver backed by fake.
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
	// Decision 3: "a listed domain with no valid TXT gets a 404."
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

func TestPolicy_FloodGuardBlocksSpeculativeLookup(t *testing.T) {
	origin := testOutpoint(25, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, r := newTestPolicy(t, "origin "+origin+"\n", fake)

	// Exhaust the flood guard's burst with unrelated hosts first.
	for i := 0; i < floodGuardBurst; i++ {
		r.AllowSpeculative()
	}

	_, ok := p.Allowed(context.Background(), "unlisted-host.example.org")
	if ok {
		t.Fatal("expected refusal once the flood guard's burst is exhausted")
	}
	if fake.callCount() != 0 {
		t.Fatalf("expected the flood guard to block the lookup itself, got %d calls", fake.callCount())
	}
}
