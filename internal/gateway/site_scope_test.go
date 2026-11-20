package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/content"
)

// buildScopeTestSiteHandler builds a SiteHandler allowing exactly one
// domain (via a fake TXT answer) mapped to origin, serving g for it, with
// the given content_scope mode.
func buildScopeTestSiteHandler(t *testing.T, domain, origin string, g *graphContent, scope string) *SiteHandler {
	t.Helper()
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain "+domain+"\n", fake)
	return NewSiteHandler(SiteHandlerConfig{
		Policy:       p,
		Content:      g,
		ContentScope: scope,
	})
}

func TestSiteHandler_InScopeContentServedWithImmutableHeaders(t *testing.T) {
	origin := testOutpoint(840, 0)
	child := testOutpoint(841, 0)
	g := newGraphContent()
	g.set(origin, "<html>"+ref(child)+"</html>")
	g.set(child, "<html>leaf</html>")
	sh := buildScopeTestSiteHandler(t, "scope.example.org", origin, g, "site")

	req := httptest.NewRequest("GET", "http://scope.example.org/content/"+child, nil)
	req.Host = "scope.example.org"
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for an in-scope outpoint, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "<html>leaf</html>" {
		t.Fatalf("unexpected body %q", w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != content.ImmutableCacheControl {
		t.Fatalf("expected immutable Cache-Control %q, got %q", content.ImmutableCacheControl, cc)
	}
	if got := w.Header().Get(outpointHeader); got != child {
		t.Fatalf("expected %s=%q, got %q", outpointHeader, child, got)
	}
	if got := w.Header().Get(originHeader); got != origin {
		t.Fatalf("expected %s=%q, got %q", originHeader, origin, got)
	}
}

func TestSiteHandler_OutOfScopeContentIs404(t *testing.T) {
	origin := testOutpoint(850, 0)
	outOfScope := testOutpoint(851, 0) // never referenced from origin
	g := newGraphContent()
	g.set(origin, "<html>no refs here</html>")
	g.set(outOfScope, "<html>never referenced</html>")
	sh := buildScopeTestSiteHandler(t, "scope2.example.org", origin, g, "site")

	req := httptest.NewRequest("GET", "http://scope2.example.org/content/"+outOfScope, nil)
	req.Host = "scope2.example.org"
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an out-of-scope outpoint, got %d", w.Code)
	}
	if got := sh.Stats()["gateway_scope_refused"]; got != 1 {
		t.Fatalf("expected gateway_scope_refused=1, got %d", got)
	}
}

func TestSiteHandler_ContentScopeAnyServesUnconditionally(t *testing.T) {
	origin := testOutpoint(860, 0)
	outOfScope := testOutpoint(861, 0) // never referenced from origin
	g := newGraphContent()
	g.set(origin, "<html>no refs here</html>")
	g.set(outOfScope, "<html>served anyway</html>")
	sh := buildScopeTestSiteHandler(t, "scope3.example.org", origin, g, "any")

	req := httptest.NewRequest("GET", "http://scope3.example.org/content/"+outOfScope, nil)
	req.Host = "scope3.example.org"
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 under content_scope=any even for an unreferenced outpoint, got %d", w.Code)
	}
	if w.Body.String() != "<html>served anyway</html>" {
		t.Fatalf("unexpected body %q", w.Body.String())
	}
	if got := sh.Stats()["gateway_scope_refused"]; got != 0 {
		t.Fatalf("expected content_scope=any to never refuse on scope, got gateway_scope_refused=%d", got)
	}
}

func TestSiteHandler_RootOutpointAlwaysInScope(t *testing.T) {
	// The root outpoint itself (the trivial match in InScope) must be
	// servable via /content/ too, with no scan needed.
	origin := testOutpoint(870, 0)
	g := newGraphContent()
	g.set(origin, "<html>root body</html>")
	sh := buildScopeTestSiteHandler(t, "scope4.example.org", origin, g, "site")

	req := httptest.NewRequest("GET", "http://scope4.example.org/content/"+origin, nil)
	req.Host = "scope4.example.org"
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for the origin outpoint itself, got %d", w.Code)
	}
}
