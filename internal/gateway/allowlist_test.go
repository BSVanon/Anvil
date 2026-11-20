package gateway

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"simple", "Example.ORG", "example.org", true},
		{"trailing dot stripped", "example.org.", "example.org", true},
		{"punycode allowed", "xn--mnchen-3ya.de", "xn--mnchen-3ya.de", true},
		{"raw unicode rejected", "münchen.de", "", false},
		{"empty rejected", "", "", false},
		{"leading hyphen label rejected", "-bad.example.org", "", false},
		{"trailing hyphen label rejected", "bad-.example.org", "", false},
		{"underscore rejected (not LDH)", "bad_domain.org", "", false},
		{"multi-label subdomain", "sub.Example.ORG", "sub.example.org", true},
		// N2: a bare IP literal is never a meaningful "domain" entry.
		{"IPv4 literal rejected", "127.0.0.1", "", false},
		{"IPv4 literal rejected (public-looking)", "203.0.113.42", "", false},
		{"IPv6 literal rejected (loopback)", "::1", "", false},
		{"IPv6 literal rejected (full form)", "2001:db8::1", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := validateDomain(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("validateDomain(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestParseSitesFile(t *testing.T) {
	origin := testOutpoint(10, 0)

	t.Run("comments and blanks are skipped", func(t *testing.T) {
		snap, err := parseSitesFile([]byte("# a comment\n\n  \ndomain example.org\n"))
		if err != nil {
			t.Fatal(err)
		}
		if !snap.HasDomain("example.org") {
			t.Fatal("expected example.org to be allowed")
		}
	})

	t.Run("domain and origin entries", func(t *testing.T) {
		body := "domain example.org\norigin " + origin + "\n"
		snap, err := parseSitesFile([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if !snap.HasDomain("example.org") || !snap.HasOrigin(origin) {
			t.Fatal("expected both the domain and origin entries to be present")
		}
	})

	t.Run("unknown entry kind fails", func(t *testing.T) {
		if _, err := parseSitesFile([]byte("bogus example.org\n")); err == nil {
			t.Fatal("expected an error for an unknown entry kind")
		}
	})

	t.Run("invalid domain fails the whole file", func(t *testing.T) {
		if _, err := parseSitesFile([]byte("domain münchen.de\n")); err == nil {
			t.Fatal("expected an error for an invalid domain")
		}
	})

	t.Run("invalid origin fails the whole file", func(t *testing.T) {
		if _, err := parseSitesFile([]byte("origin not-an-outpoint\n")); err == nil {
			t.Fatal("expected an error for an invalid origin")
		}
	})

	t.Run("malformed line fails", func(t *testing.T) {
		if _, err := parseSitesFile([]byte("domain\n")); err == nil {
			t.Fatal("expected an error for a line missing its value")
		}
	})
}

// countingHandler counts slog records so a test can assert "logs once per
// mtime" without depending on log output formatting.
type countingHandler struct {
	count *int
}

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingHandler) Handle(context.Context, slog.Record) error {
	*h.count++
	return nil
}
func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }

func TestAllowlist_HotReloadAddAndRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway-sites.conf")
	writeAt(t, path, "domain one.example.org\n", time.Now())

	a := NewAllowlist(path, "", slog.Default())
	if !a.Snapshot().HasDomain("one.example.org") {
		t.Fatal("expected one.example.org to be allowed on initial load")
	}
	if a.Snapshot().HasDomain("two.example.org") {
		t.Fatal("two.example.org should not be allowed yet")
	}

	// Add a site — picked up on the next Reload, no restart.
	writeAt(t, path, "domain one.example.org\ndomain two.example.org\n", time.Now().Add(time.Second))
	a.Reload()
	if !a.Snapshot().HasDomain("two.example.org") {
		t.Fatal("expected two.example.org to be allowed after reload")
	}

	// Remove a site — also picked up on the next Reload.
	writeAt(t, path, "domain two.example.org\n", time.Now().Add(2*time.Second))
	a.Reload()
	snap := a.Snapshot()
	if snap.HasDomain("one.example.org") {
		t.Fatal("expected one.example.org to be removed after reload")
	}
	if !snap.HasDomain("two.example.org") {
		t.Fatal("expected two.example.org to remain allowed")
	}
}

func TestAllowlist_BadFileKeepsLastGoodSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway-sites.conf")
	writeAt(t, path, "domain good.example.org\n", time.Now())

	var logCount int
	logger := slog.New(countingHandler{count: &logCount})
	a := NewAllowlist(path, "", logger)
	if !a.Snapshot().HasDomain("good.example.org") {
		t.Fatal("expected good.example.org to be allowed on initial load")
	}

	// Corrupt the file.
	writeAt(t, path, "this is not a valid line\n", time.Now().Add(time.Second))
	a.Reload()
	if !a.Snapshot().HasDomain("good.example.org") {
		t.Fatal("expected the last good snapshot to be kept after a bad reload")
	}
	if logCount != 1 {
		t.Fatalf("expected exactly 1 log line for the bad mtime, got %d", logCount)
	}

	// Reload again with the SAME bad file (same mtime): must not log again.
	a.Reload()
	if logCount != 1 {
		t.Fatalf("expected no additional log line for the same mtime, got %d total", logCount)
	}

	// Fix the file: the good snapshot updates again.
	writeAt(t, path, "domain fixed.example.org\n", time.Now().Add(2*time.Second))
	a.Reload()
	if !a.Snapshot().HasDomain("fixed.example.org") {
		t.Fatal("expected the snapshot to update once the file is fixed")
	}
}

func TestAllowlist_MissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.conf")

	var logCount int
	logger := slog.New(countingHandler{count: &logCount})
	a := NewAllowlist(path, "", logger)
	if a.Snapshot().HasAnyOrigin() || a.Snapshot().HasDomain("anything") {
		t.Fatal("expected an empty snapshot for a missing sites file")
	}
	if logCount != 0 {
		t.Fatalf("expected no warning for a simply-missing file, got %d", logCount)
	}
}

// TestAllowlist_APIHostDomainEntryIgnoredOnReload is D2's hot-reload
// overlap rule: a "domain" entry equal to api_host is stripped from the
// snapshot on load (and on every subsequent reload), with exactly one
// warning per bad mtime, rather than silently sitting in the snapshot as
// an "allowed" site that Router's api_host-first ordering happens to
// shadow.
func TestAllowlist_APIHostDomainEntryIgnoredOnReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway-sites.conf")
	writeAt(t, path, "domain admin.example.org\ndomain site.example.org\n", time.Now())

	var logCount int
	logger := slog.New(countingHandler{count: &logCount})
	a := NewAllowlist(path, "admin.example.org", logger)

	if a.Snapshot().HasDomain("admin.example.org") {
		t.Fatal("expected the api_host domain entry to be ignored on initial load")
	}
	if !a.Snapshot().HasDomain("site.example.org") {
		t.Fatal("expected the other domain entry to remain allowed")
	}
	if logCount != 1 {
		t.Fatalf("expected exactly 1 warning for the overlap, got %d", logCount)
	}

	// Reload with the SAME bad overlap (same mtime): must not log again.
	a.Reload()
	if logCount != 1 {
		t.Fatalf("expected no additional warning for the same mtime, got %d total", logCount)
	}

	// A fresh edit (new mtime) that still lists api_host as a domain logs
	// again — and the entry is still ignored.
	writeAt(t, path, "domain admin.example.org\n", time.Now().Add(time.Second))
	a.Reload()
	if a.Snapshot().HasDomain("admin.example.org") {
		t.Fatal("expected the api_host domain entry to still be ignored after reload")
	}
	if logCount != 2 {
		t.Fatalf("expected a second warning for the new mtime's overlap, got %d total", logCount)
	}
}

// writeAt writes body to path and sets its mtime explicitly, so reload
// tests don't depend on filesystem timestamp resolution between writes.
func writeAt(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}
