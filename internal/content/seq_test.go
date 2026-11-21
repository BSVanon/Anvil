package content

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeVersions resolves an origin's versions from a list.
type fakeVersions struct {
	versions  map[string][]string // origin -> its versions, 0 the origin
	content   map[string]string   // location -> effective content outpoint
	pending   map[string]bool     // outpoint -> not yet mined
	immutable map[string]bool     // outpoint -> at least six confirmations
	err       error
}

func (f *fakeVersions) ResolveVersion(origin string, seq int) (string, string, bool, error) {
	if f.err != nil {
		return "", "", false, f.err
	}
	vs, ok := f.versions[origin]
	if !ok {
		return "", "", false, ErrNotTracked
	}
	if seq == -1 {
		seq = len(vs) - 1
	}
	if seq >= len(vs) {
		return "", "", false, ErrNoVersion
	}
	outpoint := vs[seq]
	contentAt := f.content[outpoint]
	if contentAt == "" {
		contentAt = outpoint
	}
	return outpoint, contentAt, f.pending[outpoint], nil
}

func (f *fakeVersions) ResolveVersionAt(locator string, relativeSeq int) (VersionLocation, error) {
	if f.err != nil {
		return VersionLocation{}, f.err
	}
	for origin, vs := range f.versions {
		start := -1
		for i, outpoint := range vs {
			if outpoint == locator {
				start = i
				break
			}
		}
		if start < 0 {
			continue
		}
		seq := start + relativeSeq
		if relativeSeq == -1 {
			seq = len(vs) - 1
		}
		if seq < start || seq >= len(vs) {
			return VersionLocation{}, ErrNoVersion
		}
		outpoint := vs[seq]
		contentAt := f.content[outpoint]
		if contentAt == "" {
			contentAt = outpoint
		}
		return VersionLocation{
			Origin: origin, Outpoint: outpoint, ContentOutpoint: contentAt,
			Seq: seq, Pending: f.pending[outpoint], Immutable: f.immutable[outpoint],
		}, nil
	}
	return VersionLocation{}, ErrNotTracked
}

// versionedTx is one transaction whose outputs 0 and 1 are inscribed "v0"
// and "v1", and whose output 2 is a plain lock.
func versionedTx(t *testing.T) (txid, rawHex string) {
	t.Helper()
	lock := func(body string) []byte {
		return envScript(t, hdr, "51", push([]byte("text/plain")), "00", push([]byte(body)), "68", p2pk)
	}
	tx := buildTestTx([][]byte{lock("v0"), lock("v1"), envScript(t, p2pk)})
	return realTxid(tx), hex.EncodeToString(tx)
}

func serveSeq(s *Server, origin, query string, preset http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/content/"+origin+query, nil)
	req.SetPathValue("origin", origin)
	rec := httptest.NewRecorder()
	for k, v := range preset {
		rec.Header()[k] = v
	}
	s.ServeContent(rec, req)
	return rec
}

func TestSeqServesTrackedVersions(t *testing.T) {
	txid, raw := versionedTx(t)
	origin, v1, moved := txid+"_0", txid+"_1", txid+"_2"
	s := NewServer("", &fakeTxSource{rawHex: raw}, nil, nil)
	s.SetVersions(&fakeVersions{
		versions:  map[string][]string{origin: {origin, v1, moved}},
		content:   map[string]string{moved: v1},
		pending:   map[string]bool{v1: true, moved: true},
		immutable: map[string]bool{origin: true},
	}, 30*time.Second)

	for _, c := range []struct{ path, query, body, outpoint, cache, ordSeq string }{
		{origin, "?seq=0", "v0", origin, VersionImmutableCacheControl, "0"},
		{txid, "?seq=0", "v0", origin, VersionImmutableCacheControl, "0"},
		{origin + ":0", "", "v0", origin, VersionImmutableCacheControl, "0"},
		{origin, "?seq=1", "v1", v1, "public, max-age=30", "1"}, // pending
		{origin, "?seq=2", "v1", moved, "public, max-age=30", "2"},
		{v1 + ":1", "", "v1", moved, "public, max-age=30", "2"},
		{origin, "?seq=-1", "v1", moved, "no-store", "2"},
		{origin + ":-1", "", "v1", moved, "no-store", "2"},
	} {
		rec := serveSeq(s, c.path, c.query, nil)
		h := rec.Header()
		if rec.Code != http.StatusOK || rec.Body.String() != c.body || h.Get("Cache-Control") != c.cache ||
			h.Get(OriginHeader) != origin || h.Get(OutpointHeader) != c.outpoint || h.Get(OrdSeqHeader) != c.ordSeq ||
			h.Get("Content-Type") != "text/plain" || h.Get("Access-Control-Allow-Origin") != "*" ||
			h.Get("Access-Control-Expose-Headers") != "X-Origin, X-Outpoint, X-Ord-Seq" {
			t.Fatalf("%s%s: %d %q %v", c.path, c.query, rec.Code, rec.Body.String(), h)
		}
	}
	rec := serveSeq(s, origin, "?seq=0", http.Header{"Access-Control-Expose-Headers": {"X-Other"}})
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "X-Other, X-Origin, X-Outpoint, X-Ord-Seq" {
		t.Fatalf("expose headers %q", got)
	}
	if rec := serveSeq(s, origin, "?seq=3", nil); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), ErrNoVersion.Error()) {
		t.Fatalf("a version that does not exist: %d %q", rec.Code, rec.Body.String())
	}
}

func TestSeqOnAnUntrackedOriginSaysSo(t *testing.T) {
	txid, raw := versionedTx(t)
	s := NewServer("", &fakeTxSource{rawHex: raw}, nil, nil)
	for _, set := range []bool{false, true} {
		if set {
			s.SetVersions(&fakeVersions{versions: map[string][]string{}}, time.Minute)
		}
		rec := serveSeq(s, txid+"_0", "?seq=0", nil)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not tracked by this node") {
			t.Fatalf("hook set %v: %d %q", set, rec.Code, rec.Body.String())
		}
	}
	s.SetVersions(nil, 0)
	if rec := serveSeq(s, txid+"_0", "?seq=-1", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("after the hook is cleared: %d", rec.Code)
	}
}

func TestSeqRefusals(t *testing.T) {
	txid, raw := versionedTx(t)
	origin := txid + "_0"
	s := NewServer("", &fakeTxSource{rawHex: raw}, nil, nil)
	f := &fakeVersions{versions: map[string][]string{origin: {origin, txid + "_2"}}}
	s.SetVersions(f, time.Minute)
	for _, c := range []struct {
		path, query string
		code        int
	}{
		{origin, "?seq=", http.StatusBadRequest},
		{origin, "?seq=x", http.StatusBadRequest},
		{origin, "?seq=-2", http.StatusBadRequest},
		{"xyz_0", "?seq=0", http.StatusBadRequest},
		{txid + "_-1", "?seq=0", http.StatusBadRequest},
		{origin, "?seq=1", http.StatusNotFound}, // the version's output holds no inscription
	} {
		if rec := serveSeq(s, c.path, c.query, nil); rec.Code != c.code {
			t.Fatalf("%s%s: %d %q, want %d", c.path, c.query, rec.Code, rec.Body.String(), c.code)
		}
	}
	f.err = errors.New("store failed")
	if rec := serveSeq(s, origin, "?seq=0", nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("a failed lookup: %d", rec.Code)
	}
	f.err = nil
	s2 := NewServer("http://127.0.0.1:1", &fakeTxSource{err: errors.New("down")}, nil, nil)
	s2.SetVersions(f, time.Minute)
	if rec := serveSeq(s2, origin, "?seq=0", nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("a failed fetch: %d", rec.Code)
	}
}

// Without ?seq, /content answers exactly as it did before versions existed,
// whether or not a resolver is set.
func TestContentWithoutSeqIsUnchanged(t *testing.T) {
	txid, raw := versionedTx(t)
	plain := NewServer("", &fakeTxSource{rawHex: raw}, nil, nil)
	tracking := NewServer("", &fakeTxSource{rawHex: raw}, nil, nil)
	tracking.SetVersions(&fakeVersions{versions: map[string][]string{txid + "_0": {txid + "_0", txid + "_1"}}}, time.Minute)
	for _, path := range []string{txid + "_0", txid + "_1", txid, txid + "_2", txid + "_9", "short"} {
		for _, query := range []string{"", "?other=1"} {
			a, b := serveSeq(plain, path, query, nil), serveSeq(tracking, path, query, nil)
			if a.Code != b.Code || a.Body.String() != b.Body.String() || !reflect.DeepEqual(a.Header(), b.Header()) {
				t.Fatalf("%s%s: %d %q %v vs %d %q %v", path, query, a.Code, a.Body.String(), a.Header(), b.Code, b.Body.String(), b.Header())
			}
			if a.Header().Get(OriginHeader) != "" {
				t.Fatalf("%s%s: a mirror header without ?seq", path, query)
			}
		}
	}
}
