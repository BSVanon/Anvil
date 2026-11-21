package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSiteHandler_Counters verifies counters for a mix of
// allowed, policy-disallowed and scope-refused requests must land in the
// right aggregate counters, with no per-client or per-site breakdown.
func TestSiteHandler_Counters(t *testing.T) {
	origin := testOutpoint(900, 0)
	child := testOutpoint(901, 0)      // referenced from origin: in scope
	outOfScope := testOutpoint(902, 0) // never referenced: out of scope

	dir := t.TempDir()
	sitesPath := filepath.Join(dir, "gateway-sites.conf")
	if err := os.WriteFile(sitesPath, []byte("domain allowed.example.org\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	allow := NewAllowlist(sitesPath, "", slog.Default())

	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	clock := time.Now()
	resolver := newTestResolver(fake, &clock)

	// Share one Counters between the Resolver and the SiteHandler, as the
	// production wiring will: Stats() must reflect gateway-wide totals,
	// not just the SiteHandler's own increments.
	counters := &Counters{}
	resolver.stats = counters
	policy := NewPolicy(allow, resolver)

	g := newGraphContent()
	g.set(origin, "<html>"+ref(child)+"</html>")
	g.set(child, "<html>leaf</html>")
	g.set(outOfScope, "<html>never referenced</html>")

	sh := NewSiteHandler(SiteHandlerConfig{
		Policy:       policy,
		Content:      g,
		ContentScope: "site",
		Counters:     counters,
	})

	// 1. Allowed, in scope.
	req1 := httptest.NewRequest("GET", "http://allowed.example.org/content/"+child, nil)
	req1.Host = "allowed.example.org"
	w1 := httptest.NewRecorder()
	sh.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected the allowed in-scope request to succeed, got %d: %s", w1.Code, w1.Body.String())
	}

	// 2. A Host with no domain entry and no origin entries to speculate
	// against at all — Policy refuses without any TXT lookup.
	req2 := httptest.NewRequest("GET", "http://not-allowed.example.org/", nil)
	req2.Host = "not-allowed.example.org"
	w2 := httptest.NewRecorder()
	sh.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected the disallowed Host to 404, got %d", w2.Code)
	}

	// 3. Allowed Host, but a content path outside its scope.
	req3 := httptest.NewRequest("GET", "http://allowed.example.org/content/"+outOfScope, nil)
	req3.Host = "allowed.example.org"
	w3 := httptest.NewRecorder()
	sh.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("expected the out-of-scope request to 404, got %d", w3.Code)
	}

	stats := sh.Stats()
	if got := stats["gateway_requests"]; got != 3 {
		t.Fatalf("gateway_requests = %d, want 3", got)
	}
	if got := stats["gateway_not_found"]; got != 1 {
		t.Fatalf("gateway_not_found = %d, want 1 (only the disallowed Host)", got)
	}
	if got := stats["gateway_scope_refused"]; got != 1 {
		t.Fatalf("gateway_scope_refused = %d, want 1", got)
	}
	// Exactly 1: request 1 misses the cache and looks up; request 3 reuses
	// the still-fresh positive cache entry for the same host.
	if got := stats["gateway_txt_lookups"]; got != 1 {
		t.Fatalf("gateway_txt_lookups = %d, want 1", got)
	}
	if got := stats["gateway_txt_stale_served"]; got != 0 {
		t.Fatalf("gateway_txt_stale_served = %d, want 0", got)
	}
}
