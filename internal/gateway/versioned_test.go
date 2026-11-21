package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/content"
)

// trackedVersions is a Versions with a version history, as the node's
// tracker is: versions lists each tracked origin's versions, 0 the origin.
type trackedVersions struct {
	versions map[string][]string
	pending  map[string]bool
}

func (v *trackedVersions) Latest(origin string) (string, error) {
	if vs := v.versions[origin]; len(vs) > 0 {
		return vs[len(vs)-1], nil
	}
	return origin, nil
}

func (v *trackedVersions) At(origin string, seq int) (string, error) {
	out, _, err := v.ResolveVersion(origin, seq)
	return out, err
}

func (v *trackedVersions) ResolveVersion(origin string, seq int) (string, bool, error) {
	vs, ok := v.versions[origin]
	if !ok {
		return "", false, content.ErrNotTracked
	}
	if seq == -1 {
		seq = len(vs) - 1
	}
	if seq >= len(vs) {
		return "", false, content.ErrNoVersion
	}
	return vs[seq], v.pending[vs[seq]], nil
}

func (v *trackedVersions) History(origin string) []string { return v.versions[origin] }

func versionedSite(t *testing.T, origin string, g contentFetcher, v Versions, scope string) *SiteHandler {
	t.Helper()
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain site.example.org\n", fake)
	return NewSiteHandler(SiteHandlerConfig{Policy: p, Content: g, Versions: v, ContentScope: scope, RootMaxAge: 30 * time.Second})
}

func getSite(sh *SiteHandler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "http://site.example.org"+path, nil)
	req.Host = "site.example.org"
	w := httptest.NewRecorder()
	sh.ServeHTTP(w, req)
	return w
}

// A site origin with three versions: the origin and v1 each reference an
// asset of their own, v2 (the latest, not yet mined) references nothing,
// and the origin also references another tracked origin and an untracked
// one.
type versionedFixture struct {
	origin, v1, v2, oldAsset, v1Asset, lib, libV1, plain, outside string
	g                                                             *graphContent
	v                                                             *trackedVersions
}

func newVersionedFixture() *versionedFixture {
	f := &versionedFixture{
		origin: testOutpoint(900, 0), v1: testOutpoint(901, 0), v2: testOutpoint(902, 0),
		oldAsset: testOutpoint(903, 0), v1Asset: testOutpoint(904, 0),
		lib: testOutpoint(905, 0), libV1: testOutpoint(906, 0),
		plain: testOutpoint(907, 0), outside: testOutpoint(908, 0),
		g: newGraphContent(),
	}
	f.g.set(f.origin, "<html>v0"+ref(f.oldAsset)+ref(f.lib)+ref(f.plain)+"</html>")
	f.g.set(f.v1, "<html>v1"+ref(f.v1Asset)+"</html>")
	f.g.set(f.v2, "<html>v2</html>")
	for _, o := range []string{f.oldAsset, f.v1Asset, f.lib, f.libV1, f.plain, f.outside} {
		f.g.set(o, "<html>"+o+"</html>")
	}
	f.v = &trackedVersions{
		versions: map[string][]string{f.origin: {f.origin, f.v1, f.v2}, f.lib: {f.lib, f.libV1}},
		pending:  map[string]bool{f.v2: true},
	}
	return f
}

func TestSiteServesTrackedVersions(t *testing.T) {
	f := newVersionedFixture()
	sh := versionedSite(t, f.origin, f.g, f.v, "site")
	short := "public, max-age=30"
	for _, c := range []struct {
		path, body, origin, outpoint, cache string
	}{
		{"/content/" + f.origin + "?seq=0", "<html>v0", f.origin, f.origin, content.ImmutableCacheControl},
		{"/content/" + f.origin + "?seq=1", "<html>v1", f.origin, f.v1, content.ImmutableCacheControl},
		{"/content/" + f.origin + "?seq=2", "<html>v2", f.origin, f.v2, short}, // not yet mined
		{"/content/" + f.origin + "?seq=-1", "<html>v2", f.origin, f.v2, short},
		{"/content/" + f.lib + "?seq=-1", "<html>" + f.libV1, f.lib, f.libV1, short}, // a tracked origin the site references
		{"/content/" + f.lib + "?seq=1", "<html>" + f.libV1, f.lib, f.libV1, content.ImmutableCacheControl},
	} {
		w := getSite(sh, c.path)
		h := w.Header()
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Body.String(), c.body) || h.Get(originHeader) != c.origin ||
			h.Get(outpointHeader) != c.outpoint || h.Get("Cache-Control") != c.cache || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %d %q %v", c.path, w.Code, w.Body.String(), h)
		}
	}
	for _, c := range []struct {
		path string
		code int
		says string
	}{
		{"/content/" + f.origin + "?seq=3", http.StatusNotFound, content.ErrNoVersion.Error()},
		{"/content/" + f.plain + "?seq=0", http.StatusNotFound, content.ErrNotTracked.Error()}, // in scope, not tracked
		{"/content/" + f.outside + "?seq=0", http.StatusNotFound, ""},                          // out of scope
		{"/content/" + f.origin + "?seq=x", http.StatusBadRequest, "invalid seq"},
		{"/content/" + f.origin + "?seq=-2", http.StatusBadRequest, "invalid seq"},
		{"/?seq=1", http.StatusNotFound, ""},
	} {
		if w := getSite(sh, c.path); w.Code != c.code || !strings.Contains(w.Body.String(), c.says) {
			t.Fatalf("%s: %d %q, want %d %q", c.path, w.Code, w.Body.String(), c.code, c.says)
		}
	}
	if got := sh.Stats()["gateway_scope_refused"]; got != 1 {
		t.Fatalf("scope refusals %d, want 1", got)
	}
}

// Every version of the site's origin roots its content scope, so an asset
// only an earlier version references stays in scope.
func TestEveryVersionRootsTheSiteScope(t *testing.T) {
	f := newVersionedFixture()
	sh := versionedSite(t, f.origin, f.g, f.v, "site")
	for _, path := range []string{f.v1, f.v1Asset, f.oldAsset, f.v2, f.origin} {
		if w := getSite(sh, "/content/"+path); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != content.ImmutableCacheControl {
			t.Fatalf("%s: %d %q", path, w.Code, w.Body.String())
		}
	}
	if w := getSite(sh, "/content/"+f.outside); w.Code != http.StatusNotFound {
		t.Fatalf("an unreferenced outpoint: %d", w.Code)
	}
	// Without a history, an earlier version's own asset is out of scope.
	plain := versionedSite(t, f.origin, f.g, struct{ Versions }{f.v}, "site")
	if w := getSite(plain, "/content/"+f.v1Asset); w.Code != http.StatusNotFound {
		t.Fatalf("without a history: %d", w.Code)
	}
}

// A node that tracks no versions answers ?seq on a site as untracked, and
// everything else as before.
func TestSiteSeqWithoutTrackingIsNotTracked(t *testing.T) {
	f := newVersionedFixture()
	sh := versionedSite(t, f.origin, f.g, nil, "site")
	if w := getSite(sh, "/content/"+f.origin+"?seq=0"); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), content.ErrNotTracked.Error()) {
		t.Fatalf("?seq without tracking: %d %q", w.Code, w.Body.String())
	}
	if w := getSite(sh, "/content/"+f.origin); w.Code != http.StatusOK || w.Header().Get(outpointHeader) != f.origin {
		t.Fatalf("without ?seq: %d %v", w.Code, w.Header())
	}
	if w := getSite(sh, "/"); w.Code != http.StatusOK || w.Header().Get(outpointHeader) != f.origin {
		t.Fatalf("/: %d %v", w.Code, w.Header())
	}
}

func TestMirrorHeadersMatchTheContentServers(t *testing.T) {
	if originHeader != content.OriginHeader || outpointHeader != content.OutpointHeader {
		t.Fatalf("site %s/%s, content %s/%s", originHeader, outpointHeader, content.OriginHeader, content.OutpointHeader)
	}
}

func TestVersionRootsAreBoundedAndEndAtTheLatest(t *testing.T) {
	origin := testOutpoint(1, 0)
	history := []string{origin}
	for i := 2; i <= scopeMaxVersionRoots+10; i++ {
		history = append(history, testOutpoint(i, 0))
	}
	c := &scopeCache{history: func(string) []string { return history }}
	latest := history[len(history)-3] // the history ran on past the latest asked about
	got, rooted := c.versionRoots(origin, latest)
	if !rooted || len(got) != scopeMaxVersionRoots || got[0] != history[len(history)-4] {
		t.Fatalf("rooted %v, %d roots from %s", rooted, len(got), got[0])
	}
	for _, v := range got {
		if v == origin || v == latest {
			t.Fatalf("%s repeated as a version root", v)
		}
	}
	if _, rooted := c.versionRoots(origin, testOutpoint(99999, 0)); rooted {
		t.Fatal("a latest missing from the history counted as rooted")
	}
	if got, rooted := c.versionRoots(origin, origin); !rooted || got != nil {
		t.Fatalf("an origin that is its own latest: %v %v", got, rooted)
	}
}

// The scope cache keeps one result per origin: a new latest version
// replaces the result for the last one.
func TestScopeCacheKeepsOneResultPerOrigin(t *testing.T) {
	f := newVersionedFixture()
	sc := newScopeCache(f.g)
	sc.history = f.v.History
	for _, latest := range []string{f.v1, f.v2} {
		if !sc.InScope(context.Background(), f.origin, latest, f.oldAsset) {
			t.Fatalf("latest %s: the origin's asset is out of scope", latest)
		}
	}
	sc.InScope(context.Background(), f.lib, f.libV1, f.outside)
	if len(sc.byKey) != 2 || sc.byKey[f.origin+"|"+f.v2] == nil {
		t.Fatalf("cached %d results: %v", len(sc.byKey), sc.byKey)
	}
}

// hostTXT answers each _ordfs.<host> TXT lookup from a map.
type hostTXT map[string]string

func (h hostTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	if origin, ok := h[strings.TrimPrefix(name, "_ordfs.")]; ok {
		return []string{"ordfs=" + origin}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestTrackedOriginsAreThePolicysOrigins(t *testing.T) {
	a, b, c, d := testOutpoint(30, 0), testOutpoint(31, 1), testOutpoint(32, 0), testOutpoint(33, 0)
	path := filepath.Join(t.TempDir(), "sites.conf")
	body := fmt.Sprintf("origin %s\norigin %s\ndomain one.example.org\ndomain two.example.org\ndomain dup.example.org\ndomain none.example.org\n", b, a)
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(ResolverConfig{})
	r.lookup = hostTXT{"one.example.org": d, "two.example.org": c, "dup.example.org": a}
	p := NewPolicy(NewAllowlist(path, "", slog.Default()), r)

	// The origin entries, sorted, then each domain's TXT target in domain
	// order: dup.example.org repeats a, and none.example.org has none.
	want := []string{a, b, d, c}
	if got := p.TrackedOrigins(context.Background(), 10); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tracked %v, want %v", got, want)
	}
	if got := p.TrackedOrigins(context.Background(), 3); fmt.Sprint(got) != fmt.Sprint(want[:3]) {
		t.Fatalf("limit 3: %v", got)
	}
	if got := p.TrackedOrigins(context.Background(), 0); got != nil {
		t.Fatalf("limit 0: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := p.TrackedOrigins(ctx, 10); fmt.Sprint(got) != fmt.Sprint(want[:2]) {
		t.Fatalf("a cancelled refresh looked up domains: %v", got)
	}
}
