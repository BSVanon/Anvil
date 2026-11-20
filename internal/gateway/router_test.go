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

// TestRouter_EmptyAPIHostIsWildcard pins the design decision that makes
// decision 2's "On today's API listener (:9333), every Host except an
// allowed site keeps today's behaviour" true: an empty APIHost is the
// wildcard the :9333 wiring uses, so local tools, mesh peers and tests —
// which send all kinds of Host headers — keep reaching the API exactly as
// they do today, while an allowed site (and only an allowed site) still
// peels off to Sites.
func TestRouter_EmptyAPIHostIsWildcard(t *testing.T) {
	sites := newTestSiteHandler(t, "site.example.org", testOutpoint(33, 0))
	rt := &Router{API: stubAPIHandler(), Sites: sites, APIHost: ""}

	req := httptest.NewRequest("GET", "http://whatever-a-test-sends/status", nil)
	req.Host = "whatever-a-test-sends"
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, req)

	if w.Code != http.StatusOK || w.Body.String() != "API" {
		t.Fatalf("expected an empty APIHost to default any non-site Host to the API, got %d %q", w.Code, w.Body.String())
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
// port (decision 7).
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
