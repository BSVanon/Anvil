package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeContent is a controllable contentFetcher for tests that don't need
// a real internal/content.Server.
type fakeContent struct {
	data []byte
	ct   string
	err  error
}

func (f *fakeContent) Inscription(context.Context, string, int) ([]byte, string, error) {
	if f.err != nil {
		return nil, "", f.err
	}
	return f.data, f.ct, nil
}

func stubAPIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("API"))
	})
}

// newTestSiteHandler builds a minimal, real SiteHandler that allows
// exactly one domain, for Router dispatch tests.
func newTestSiteHandler(t *testing.T, domain, origin string) *SiteHandler {
	t.Helper()
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain "+domain+"\n", fake)
	return NewSiteHandler(SiteHandlerConfig{
		Policy:       p,
		Content:      &fakeContent{data: []byte("hello"), ct: "text/plain"},
		ContentScope: "any", // dispatch tests don't exercise scope
	})
}

func TestRouter_APIHostReachesAPI(t *testing.T) {
	sites := newTestSiteHandler(t, "site.example.org", testOutpoint(30, 0))
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: "admin.example.org"}

	req := httptest.NewRequest("GET", "http://admin.example.org/status", nil)
	req.Host = "admin.example.org"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusOK || w.Body.String() != "API" {
		t.Fatalf("expected the API handler's response, got %d %q", w.Code, w.Body.String())
	}
}

func TestRouter_AllowedSiteReachesSiteHandler(t *testing.T) {
	origin := testOutpoint(31, 0)
	sites := newTestSiteHandler(t, "site.example.org", origin)
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: "admin.example.org"}

	req := httptest.NewRequest("GET", "http://site.example.org/", nil)
	req.Host = "site.example.org"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusOK || w.Body.String() != "hello" {
		t.Fatalf("expected the site handler's response, got %d %q", w.Code, w.Body.String())
	}
	if w.Body.String() == "API" {
		t.Fatal("must not have reached the API handler")
	}
}

func TestRouter_AnythingElseIs404(t *testing.T) {
	sites := newTestSiteHandler(t, "site.example.org", testOutpoint(32, 0))
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: "admin.example.org"}

	req := httptest.NewRequest("GET", "http://not-a-site.example.org/", nil)
	req.Host = "not-a-site.example.org"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unrecognised Host, got %d", w.Code)
	}
}

// TestRouter_EmptyAPIHostOnlyLoopbackReachesAPI verifies that an empty API host
// place of what this test used to pin under its old name
// (TestRouter_EmptyAPIHostIsWildcard): an empty APIHost is NEVER a
// wildcard. With no APIHost configured, an arbitrary, non-loopback Host
// that isn't an allowed site must fail closed to Sites' own 404 — not
// fall through to the API the way the pre-fix router.go's
// `rt.APIHost == "" || host == rt.APIHost` did. Only a loopback Host still
// reaches the API unconditionally (TestRouter_LoopbackNamesReachAPI).
func TestRouter_EmptyAPIHostOnlyLoopbackReachesAPI(t *testing.T) {
	sites := newTestSiteHandler(t, "site.example.org", testOutpoint(33, 0))
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: ""}

	req := httptest.NewRequest("GET", "http://whatever-a-test-sends/status", nil)
	req.Host = "whatever-a-test-sends"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected an empty APIHost to fail closed (404) for an arbitrary, non-loopback Host, got %d %q", w.Code, w.Body.String())
	}
}

// TestHostile_EmptyAPIHost_ConfiguredSiteStillHitsAPI makes the review's
// permanent regression. Before the fix, router.go's
// `rt.APIHost == "" || host == rt.APIHost` sent EVERY Host to the API
// whenever APIHost was empty — including an allowed, configured site,
// which should have reached Sites instead. With the fix: an allowed site
// still reaches Sites, an unrecognised Host still 404s, and a loopback
// Host (the one thing an empty APIHost still lets through) still reaches
// the API.
func TestHostile_EmptyAPIHost_ConfiguredSiteStillHitsAPI(t *testing.T) {
	origin := testOutpoint(35, 0)
	sites := newTestSiteHandler(t, "site.example.org", origin)
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: ""}

	req1 := httptest.NewRequest("GET", "http://site.example.org/", nil)
	req1.Host = "site.example.org"
	w1 := httptest.NewRecorder()
	rt.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK || w1.Body.String() != "hello" {
		t.Fatalf("expected the allowed site to reach Sites even with APIHost empty, got %d %q", w1.Code, w1.Body.String())
	}

	req2 := httptest.NewRequest("GET", "http://unknown.example.org/", nil)
	req2.Host = "unknown.example.org"
	w2 := httptest.NewRecorder()
	rt.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected an unrecognised Host to 404 even with APIHost empty, got %d", w2.Code)
	}

	req3 := httptest.NewRequest("GET", "http://placeholder.invalid/status", nil)
	req3.Host = "127.0.0.1"
	w3 := httptest.NewRecorder()
	rt.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK || w3.Body.String() != "API" {
		t.Fatalf("expected a loopback Host to reach the API even with APIHost empty, got %d %q", w3.Code, w3.Body.String())
	}
}

// TestRouter_APIHostCaseInsensitive confirms that a Host header differing
// only in case from the
// configured api_host must still match.
func TestRouter_APIHostCaseInsensitive(t *testing.T) {
	rt := &Router{API: stubAPIHandler(), Sites: nil, APIHost: "Admin.Example.ORG"}

	req := httptest.NewRequest("GET", "http://placeholder.invalid/status", nil)
	req.Host = "ADMIN.EXAMPLE.ORG"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusOK || w.Body.String() != "API" {
		t.Fatalf("expected a case-variant Host to match api_host, got %d %q", w.Code, w.Body.String())
	}
}

// TestRouter_APIHostTrailingDot confirms that a Host header with one trailing
// dot matches an
// api_host configured without one.
func TestRouter_APIHostTrailingDot(t *testing.T) {
	rt := &Router{API: stubAPIHandler(), Sites: nil, APIHost: "admin.example.org"}

	req := httptest.NewRequest("GET", "http://placeholder.invalid/status", nil)
	req.Host = "admin.example.org."
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusOK || w.Body.String() != "API" {
		t.Fatalf("expected a trailing-dot Host to match api_host, got %d %q", w.Code, w.Body.String())
	}
}

// TestRouter_LoopbackNamesReachAPI covers the loopback rule: localhost
// (any case), an IPv4 literal anywhere in 127.0.0.0/8, and ::1 (bracketed
// or bare, with or without a port) all reach the API even though none of
// them equals the configured api_host — including a loopback Host WITH a
// port.
func TestRouter_LoopbackNamesReachAPI(t *testing.T) {
	rt := &Router{API: stubAPIHandler(), Sites: nil, APIHost: "admin.example.org"}

	for _, host := range []string{
		"localhost", "LOCALHOST", "localhost:9333",
		"127.0.0.1", "127.0.0.1:9333", "127.5.5.5",
		"::1", "[::1]", "[::1]:9333",
	} {
		req := httptest.NewRequest("GET", "http://placeholder.invalid/status", nil)
		req.Host = host
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		if w.Code != http.StatusOK || w.Body.String() != "API" {
			t.Fatalf("Host %q: expected a loopback Host to reach the API, got %d %q", host, w.Code, w.Body.String())
		}
	}
}

// TestRouter_LoopbackAntiSpoof ensures a Host that merely
// looks like, contains, or sounds like a loopback name must not take
// isLoopbackHost's exact-match/IP-literal rule — only "localhost" itself
// or an actual loopback IP literal (optionally with a port, stripped by
// normalizeHost first) does. A Sites allowlist that only knows
// "site.example.org" means any of these reaching the API instead of a
// 404 proves the spoof attempt actually took the loopback rule.
func TestRouter_LoopbackAntiSpoof(t *testing.T) {
	sites := newTestSiteHandler(t, "site.example.org", testOutpoint(36, 0))
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: "admin.example.org"}

	spoofed := []string{
		"localhost.evil.com", // suffix match, not exact
		"127.0.0.1.evil.com", // looks IP-prefixed, not a valid IP literal
		"evil-localhost",     // contains "localhost", isn't it
		"xn--localhost",      // punycode-shaped, isn't "localhost" either
	}
	for _, host := range spoofed {
		req := httptest.NewRequest("GET", "http://placeholder.invalid/status", nil)
		req.Host = host
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		if w.Code == http.StatusOK && w.Body.String() == "API" {
			t.Fatalf("Host %q: must NOT take the loopback rule and reach the API, got %d %q", host, w.Code, w.Body.String())
		}
	}

	genuine := []string{"localhost", "127.0.0.2:9333", "[::1]:9333"}
	for _, host := range genuine {
		req := httptest.NewRequest("GET", "http://placeholder.invalid/status", nil)
		req.Host = host
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		if w.Code != http.StatusOK || w.Body.String() != "API" {
			t.Fatalf("Host %q: expected a genuine loopback Host to still reach the API, got %d %q", host, w.Code, w.Body.String())
		}
	}
}

func TestRouter_NilSitesIs404ForAnythingNotAPIHost(t *testing.T) {
	rt := &Router{API: stubAPIHandler(), Sites: nil, APIHost: "admin.example.org"}

	req := httptest.NewRequest("GET", "http://other.example.org/", nil)
	req.Host = "other.example.org"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 with a nil Sites, got %d", w.Code)
	}
}

// TestRouter_StripsPortFromHost confirms a Host header carrying a port
// (as real HTTP clients send) still matches a site entered without one in
// the sites file — api_host and the sites file both name hosts with no
// port.
func TestRouter_StripsPortFromHost(t *testing.T) {
	sites := newTestSiteHandler(t, "site.example.org", testOutpoint(34, 0))
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: "admin.example.org"}

	req := httptest.NewRequest("GET", "http://site.example.org:9333/", nil)
	req.Host = "site.example.org:9333"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusOK || w.Body.String() != "hello" {
		t.Fatalf("expected the port-suffixed site Host to still match, got %d %q", w.Code, w.Body.String())
	}
}
