package ordtrack

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/content"
)

// contentServer is GET /content/{origin} with ?seq answered by h's tracker.
func (h *harness) contentServer() http.Handler {
	srv := content.NewServer("http://127.0.0.1:1", rawSource{h.store}, nil, nil)
	srv.SetVersions(h.tr, time.Minute)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /content/{origin}", srv.ServeContent)
	return mux
}

func get(t *testing.T, srv http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestARestartKeepsEveryChainAndSeqServesAfterIt(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.chain.Mine(v1)
	h.observe(v1)
	moved := h.move(v1, 0, plain())
	v2 := h.move(moved, 0, h.inscribed("v2"))
	h.observe(moved)
	h.observe(v2)

	h.reopen()
	h.tr.SetTracked([]string{origin})
	h.wantTip(origin, op(v2, 0))
	h.wantLatest(origin, op(v2, 0), true)
	if got, pending := h.version(origin, 1); got != op(v1, 0) || pending {
		t.Fatalf("version 1 = %s (pending %v)", got, pending)
	}
	if h.stat("ordtrack_pending") != 2 || h.stat("ordtrack_origins") != 1 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
	if !h.tr.Active() || h.watch.Len() != 1 {
		t.Fatalf("tip not watched again: active %v, watched %d", h.tr.Active(), h.watch.Len())
	}

	srv := h.contentServer()
	for _, c := range []struct {
		query, body, outpoint, cache, ordSeq string
	}{
		{"?seq=0", "v0", origin, content.VersionImmutableCacheControl, "0"},
		{"?seq=1", "v1", op(v1, 0), "public, max-age=60", "1"},
		{"?seq=2", "v1", op(moved, 0), "public, max-age=60", "2"},
		{"?seq=3", "v2", op(v2, 0), "public, max-age=60", "3"},
		{"?seq=-1", "v2", op(v2, 0), "no-store", "3"},
	} {
		rec := get(t, srv, "/content/"+origin+c.query)
		if rec.Code != http.StatusOK || rec.Body.String() != c.body {
			t.Fatalf("%s: %d %q", c.query, rec.Code, rec.Body.String())
		}
		hd := rec.Header()
		if hd.Get(content.OriginHeader) != origin || hd.Get(content.OutpointHeader) != c.outpoint ||
			hd.Get(content.OrdSeqHeader) != c.ordSeq || hd.Get("Cache-Control") != c.cache || hd.Get("Content-Type") != "text/plain" {
			t.Fatalf("%s: headers %v", c.query, hd)
		}
		if !strings.Contains(hd.Get("Access-Control-Expose-Headers"), content.OutpointHeader) {
			t.Fatalf("%s: mirror headers not exposed: %v", c.query, hd)
		}
	}
	// A bare txid names output 0.
	if rec := get(t, srv, "/content/"+o.TxID().String()+"?seq=1"); rec.Code != http.StatusOK || rec.Body.String() != "v1" {
		t.Fatalf("bare txid: %d %q", rec.Code, rec.Body.String())
	}
	if rec := get(t, srv, "/content/"+origin+"?seq=4"); rec.Code != http.StatusNotFound {
		t.Fatalf("a version that does not exist: %d", rec.Code)
	}
	other := h.mint("other")
	rec := get(t, srv, "/content/"+op(other, 0)+"?seq=0")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not tracked") {
		t.Fatalf("an untracked origin: %d %q", rec.Code, rec.Body.String())
	}
	// Without ?seq an outpoint is served as it is today.
	if rec := get(t, srv, "/content/"+op(v1, 0)); rec.Code != http.StatusOK || rec.Body.String() != "v1" || rec.Header().Get(content.OriginHeader) != "" {
		t.Fatalf("plain content: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}

	// The unmined links loaded back still roll back.
	h.clock.advance(DefaultPendingTimeout)
	h.tr.checkPending(h.ctx)
	h.wantTip(origin, op(v1, 0))
	h.wantLatest(origin, op(v1, 0), false)
	h.reopen()
	h.wantLatest(origin, op(v1, 0), false)
	if h.stat("ordtrack_pending") != 0 {
		t.Fatalf("stats after a second restart = %v", h.tr.Stats())
	}
}

func TestRestartMigratesInscriptionOnlySequenceRecords(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	moved := h.move(v1, 0, plain())
	h.observe(v1)
	h.observe(moved)

	first, _ := h.tr.db.link(origin, 0)
	inscribed, _ := h.tr.db.link(origin, 1)
	plainLink, _ := h.tr.db.link(origin, 2)
	first.Content, first.ContentSeq = "", 0
	inscribed.Content, inscribed.ContentSeq = "", 0
	plainLink.Content, plainLink.ContentSeq, plainLink.Seq = "", 0, -1
	m := h.tr.chains[origin].m
	m.Versions = 2
	c := newChange()
	c.putLink(origin, 0, first)
	c.putLink(origin, 1, inscribed)
	c.putLink(origin, 2, plainLink)
	c.b.Delete(versionKey(origin, 2))
	c.putMeta(m)
	if err := h.tr.db.apply(c); err != nil {
		t.Fatal(err)
	}

	var migrations []string
	h.migrationStarted = func(name string) error {
		migrations = append(migrations, name)
		return nil
	}
	h.reopen()
	location, contentAt, pending, err := h.tr.ResolveVersion(origin, 2)
	if err != nil || location != op(moved, 0) || contentAt != op(v1, 0) || !pending {
		t.Fatalf("migrated sequence 2 = %s serving %s (pending %v), error %v", location, contentAt, pending, err)
	}
	metas, err := h.tr.db.metas()
	if err != nil || len(metas) != 1 || metas[0].Versions != 3 {
		t.Fatalf("migrated metadata = %+v, %v", metas, err)
	}
	if len(migrations) != 1 || migrations[0] != sequenceMigration {
		t.Fatalf("migration starts = %v", migrations)
	}
	h.reopen()
	if len(migrations) != 1 {
		t.Fatalf("clean reopen recorded migration starts = %v", migrations)
	}
}

func TestRestartBackfillsMinedBlockAnchors(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.chain.Mine(v1)
	h.observe(v1)

	c := newChange()
	for i := 0; i < 2; i++ {
		l, err := h.tr.db.link(origin, i)
		if err != nil {
			t.Fatal(err)
		}
		l.MerkleRoot = ""
		c.putLink(origin, i, l)
	}
	if err := h.tr.db.apply(c); err != nil {
		t.Fatal(err)
	}
	h.reopen()
	if _, _, _, err := h.tr.ResolveVersion(origin, -1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		l, err := h.tr.db.link(origin, i)
		if err != nil || l.MerkleRoot == "" {
			t.Fatalf("link %d anchor = %q, %v", i, l.MerkleRoot, err)
		}
	}
}
