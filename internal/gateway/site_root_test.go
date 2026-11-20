package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// buildTestSiteHandler builds a SiteHandler allowing exactly one domain
// mapped (via a fake TXT answer) to origin, serving fake content for it.
func buildTestSiteHandler(t *testing.T, domain, origin string, content *fakeContent, scope string) *SiteHandler {
	t.Helper()
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain "+domain+"\n", fake)
	return NewSiteHandler(SiteHandlerConfig{
		Policy:       p,
		Content:      content,
		ContentScope: scope,
		RootMaxAge:   60 * time.Second,
	})
}

func TestSiteHandler_RootServesLatestVersion(t *testing.T) {
	origin := testOutpoint(700, 0)
	content := &fakeContent{data: []byte("<html>hi</html>"), ct: "text/html"}
	sh := buildTestSiteHandler(t, "site.example.org", origin, content, "any")

	req := httptest.NewRequest("GET", "http://site.example.org/", nil)
	req.Host = "site.example.org"
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "<html>hi</html>" {
		t.Fatalf("unexpected body %q", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("expected content type text/html, got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Fatalf("expected short max-age Cache-Control, got %q", cc)
	}
	wantETag := `"` + origin + `"`
	if etag := w.Header().Get("ETag"); etag != wantETag {
		t.Fatalf("expected ETag %q, got %q", wantETag, etag)
	}
	if got := w.Header().Get(originHeader); got != origin {
		t.Fatalf("expected %s=%q, got %q", originHeader, origin, got)
	}
	if got := w.Header().Get(outpointHeader); got != origin {
		t.Fatalf("expected %s=%q, got %q", outpointHeader, origin, got)
	}
	if nosniff := w.Header().Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options: nosniff, got %q", nosniff)
	}
}

func TestSiteHandler_RootHonoursIfNoneMatch(t *testing.T) {
	origin := testOutpoint(701, 0)
	content := &fakeContent{data: []byte("<html>hi</html>"), ct: "text/html"}
	sh := buildTestSiteHandler(t, "site.example.org", origin, content, "any")

	// First request to learn the ETag.
	req1 := httptest.NewRequest("GET", "http://site.example.org/", nil)
	req1.Host = "site.example.org"
	w1 := httptest.NewRecorder()
	sh.ServeHTTP(w1, req1)
	etag := w1.Header().Get("ETag")

	req2 := httptest.NewRequest("GET", "http://site.example.org/", nil)
	req2.Host = "site.example.org"
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	sh.ServeHTTP(w2, req2)

	if w2.Code != http.StatusNotModified {
		t.Fatalf("expected 304 for a matching If-None-Match, got %d", w2.Code)
	}
}

func TestSiteHandler_RootMismatchedIfNoneMatchServes200(t *testing.T) {
	origin := testOutpoint(702, 0)
	content := &fakeContent{data: []byte("<html>hi</html>"), ct: "text/html"}
	sh := buildTestSiteHandler(t, "site.example.org", origin, content, "any")

	req := httptest.NewRequest("GET", "http://site.example.org/", nil)
	req.Host = "site.example.org"
	req.Header.Set("If-None-Match", `"some-other-etag"`)
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for a non-matching If-None-Match, got %d", w.Code)
	}
}
