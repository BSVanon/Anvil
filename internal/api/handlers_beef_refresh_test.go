package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
)

// GET /tx/{txid}/beef's background-refresh behavior: an unproven cached BEEF
// is served immediately while a fetch for its proven version runs, a slow
// fetch's cached fallback, refresh-slot capacity, and refresh-reservation
// eviction order. The shared fetcher test doubles and BEEF-building helpers
// these tests draw on live in handlers_beef_test.go. Split from that file
// with no behavior change (bu_b4_specs.md item 7); every test below is
// unchanged from before the split.

func TestGetBEEFRefreshesCachedUnprovenSubject(t *testing.T) {
	srv := testServer(t)
	txid, unproven, proven := makeRefreshBEEFs(t, srv, true)
	if _, err := srv.proofStore.StoreBEEF(unproven); err != nil {
		t.Fatal(err)
	}
	fetcher := &staticBEEFFetcher{beef: proven, source: spv.BEEFSourceWoC}
	srv.proofFetcher = fetcher

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
	if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "true" {
		t.Fatalf("expected refreshed proven response, got %d %q", w.Code, w.Header().Get("X-BEEF-Subject-Proven"))
	}
	if fetcher.calls != 1 {
		t.Fatalf("fetch calls = %d, want 1", fetcher.calls)
	}
	stored, err := srv.proofStore.GetBEEF(txid)
	if err != nil || string(stored) != string(proven) {
		t.Fatalf("cache was not replaced by proven BEEF: %v", err)
	}

	// The reservation remains in force for 60 seconds after a successful fetch.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
	if fetcher.calls != 1 {
		t.Fatalf("throttle allowed %d fetches, want 1", fetcher.calls)
	}
}

func TestGetBEEFRefreshFallbacksLeaveCachedCopyUntouched(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withHeader bool
		fetcher    func([]byte) *staticBEEFFetcher
	}{
		{"unproven fetch", false, func(unproven []byte) *staticBEEFFetcher {
			return &staticBEEFFetcher{beef: unproven, source: spv.BEEFSourceWoC}
		}},
		{"fetch error", false, func([]byte) *staticBEEFFetcher { return &staticBEEFFetcher{err: errors.New("upstream unavailable")} }},
		{"failed local validation", false, func(_ []byte) *staticBEEFFetcher { return &staticBEEFFetcher{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServer(t)
			txid, unproven, proven := makeRefreshBEEFs(t, srv, tc.withHeader)
			if tc.name == "failed local validation" {
				tc.fetcher = func([]byte) *staticBEEFFetcher { return &staticBEEFFetcher{beef: proven, source: spv.BEEFSourceWoC} }
			}
			if _, err := srv.proofStore.StoreBEEF(unproven); err != nil {
				t.Fatal(err)
			}
			fetcher := tc.fetcher(unproven)
			srv.proofFetcher = fetcher
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
			if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "false" {
				t.Fatalf("expected cached unproven response, got %d %q", w.Code, w.Header().Get("X-BEEF-Subject-Proven"))
			}
			stored, err := srv.proofStore.GetBEEF(txid)
			if err != nil || string(stored) != string(unproven) {
				t.Fatalf("cached BEEF changed: %v", err)
			}
		})
	}
}

func TestGetBEEFSlowRefreshServesCachedCopyThenStoresProvenBEEF(t *testing.T) {
	shortenProofRefreshWait(t, 10*time.Millisecond)
	srv := testServer(t)
	txid, unproven, proven := makeRefreshBEEFs(t, srv, true)
	if _, err := srv.proofStore.StoreBEEF(unproven); err != nil {
		t.Fatal(err)
	}
	fetcher := &delayedBEEFFetcher{
		beef:   proven,
		source: spv.BEEFSourceWoC,
		delay:  50 * time.Millisecond,
		done:   make(chan struct{}),
	}
	srv.proofFetcher = fetcher

	started := time.Now()
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
	if elapsed := time.Since(started); elapsed > proofRefreshWait+25*time.Millisecond {
		t.Fatalf("cached response took %s, want no more than %s", elapsed, proofRefreshWait+25*time.Millisecond)
	}
	if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "false" {
		t.Fatalf("expected cached unproven response, got %d %q", w.Code, w.Header().Get("X-BEEF-Subject-Proven"))
	}

	eventually(t, time.Second, func() bool {
		stored, err := srv.proofStore.GetBEEF(txid)
		return err == nil && string(stored) == string(proven)
	})
	if fetcher.calls.Load() != 1 {
		t.Fatalf("fetch calls = %d, want 1", fetcher.calls.Load())
	}
}

func TestGetBEEFRefreshCapServesDifferentCachedCopy(t *testing.T) {
	shortenProofRefreshWait(t, 10*time.Millisecond)
	srv := testServer(t)
	srv.proofRefreshSlots = make(chan struct{}, 1)
	txidA, unprovenA, provenA := makeRefreshBEEFsWithSatoshis(t, srv, true, 1000)
	txidB, unprovenB, _ := makeRefreshBEEFsWithSatoshis(t, srv, false, 1001)
	if txidA == txidB {
		t.Fatal("test transactions must have distinct IDs")
	}
	if _, err := srv.proofStore.StoreBEEF(unprovenA); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.proofStore.StoreBEEF(unprovenB); err != nil {
		t.Fatal(err)
	}
	fetcher := &delayedBEEFFetcher{beef: provenA, source: spv.BEEFSourceWoC, delay: 100 * time.Millisecond, done: make(chan struct{})}
	srv.proofFetcher = fetcher

	srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/tx/"+txidA+"/beef", nil))
	eventually(t, time.Second, func() bool { return fetcher.calls.Load() == 1 })
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txidB+"/beef", nil))
	if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "false" {
		t.Fatalf("expected cached unproven response, got %d %q", w.Code, w.Header().Get("X-BEEF-Subject-Proven"))
	}
	if fetcher.calls.Load() != 1 {
		t.Fatalf("fetch calls = %d, want 1", fetcher.calls.Load())
	}
	srv.proofRefreshMu.Lock()
	_, reserved := srv.proofRefreshes[txidB]
	srv.proofRefreshMu.Unlock()
	if reserved {
		t.Fatal("cap-rejected refresh left its reservation in place")
	}
	select {
	case <-fetcher.done:
	case <-time.After(time.Second):
		t.Fatal("slow fetch did not finish")
	}
}

func TestRefreshCachedBEEFWithoutNewServerSkipsNilSemaphore(t *testing.T) {
	fetcher := &staticBEEFFetcher{}
	srv := &Server{proofFetcher: fetcher}
	cached := []byte("cached")
	got, source, proven := srv.refreshCachedBEEF("txid", cached)
	if string(got) != string(cached) || source != spv.BEEFSourceCached || proven {
		t.Fatalf("nil semaphore result = %q, %q, %v", got, source, proven)
	}
	if fetcher.calls != 0 {
		t.Fatalf("fetch calls = %d, want 0", fetcher.calls)
	}
}

func TestGetBEEFSlowRefreshFallbacksDoNotReplaceCachedCopy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withHeader bool
		fetched    func(unproven, proven []byte) []byte
		fetchErr   error
	}{
		{name: "unproven BEEF", fetched: func(unproven, _ []byte) []byte { return unproven }},
		{name: "invalid BEEF", fetched: func(_, proven []byte) []byte { return proven }},
		{name: "fetch error", fetchErr: errors.New("upstream unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortenProofRefreshWait(t, 10*time.Millisecond)
			srv := testServer(t)
			txid, unproven, proven := makeRefreshBEEFs(t, srv, false)
			if _, err := srv.proofStore.StoreBEEF(unproven); err != nil {
				t.Fatal(err)
			}
			var fetched []byte
			if tc.fetched != nil {
				fetched = tc.fetched(unproven, proven)
			}
			fetcher := &delayedBEEFFetcher{
				beef:   fetched,
				source: spv.BEEFSourceWoC,
				err:    tc.fetchErr,
				delay:  50 * time.Millisecond,
				done:   make(chan struct{}),
			}
			srv.proofFetcher = fetcher

			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
			if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "false" {
				t.Fatalf("expected cached unproven response, got %d %q", w.Code, w.Header().Get("X-BEEF-Subject-Proven"))
			}
			select {
			case <-fetcher.done:
			case <-time.After(time.Second):
				t.Fatal("slow fetch did not finish")
			}
			eventually(t, time.Second, func() bool {
				stored, err := srv.proofStore.GetBEEF(txid)
				return err == nil && string(stored) == string(unproven)
			})
		})
	}
}

func TestReserveProofRefreshEvictsExpiredEntryBeforeOldestLiveEntry(t *testing.T) {
	srv := testServer(t)
	now := time.Now()
	expiredID := "expired"
	oldestLiveID := "oldest-live"
	srv.proofRefreshes[expiredID] = now.Add(-proofRefreshInterval - time.Second)
	srv.proofRefreshes[oldestLiveID] = now.Add(-time.Second)
	for i := 0; i < maxProofRefreshes-2; i++ {
		srv.proofRefreshes[fmt.Sprintf("live-%d", i)] = now
	}

	if !srv.reserveProofRefresh("new") {
		t.Fatal("expected refresh reservation")
	}
	if _, ok := srv.proofRefreshes[expiredID]; ok {
		t.Fatal("expired entry was not evicted")
	}
	if _, ok := srv.proofRefreshes[oldestLiveID]; !ok {
		t.Fatal("oldest live entry was evicted before expired entry")
	}
	if _, ok := srv.proofRefreshes["new"]; !ok {
		t.Fatal("new reservation was not recorded")
	}
}
