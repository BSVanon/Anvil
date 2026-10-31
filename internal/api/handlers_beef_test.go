package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

type staticBEEFFetcher struct {
	beef   []byte
	source string
	err    error
	calls  int
}

func (f *staticBEEFFetcher) FetchBEEF(string) ([]byte, string, error) {
	f.calls++
	return f.beef, f.source, f.err
}

func (f *staticBEEFFetcher) TxStatus(string) (*spv.TxStatusResult, error) {
	return nil, errors.New("not used by BEEF refresh tests")
}

type delayedBEEFFetcher struct {
	beef   []byte
	source string
	err    error
	delay  time.Duration
	done   chan struct{}
	calls  atomic.Int32
}

func (f *delayedBEEFFetcher) FetchBEEF(string) ([]byte, string, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	close(f.done)
	return f.beef, f.source, f.err
}

func (f *delayedBEEFFetcher) TxStatus(string) (*spv.TxStatusResult, error) {
	return nil, errors.New("not used by BEEF refresh tests")
}

func shortenProofRefreshWait(t *testing.T, wait time.Duration) {
	t.Helper()
	previous := proofRefreshWait
	proofRefreshWait = wait
	t.Cleanup(func() { proofRefreshWait = previous })
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
			if time.Now().After(deadline) {
				t.Fatal("condition not met before timeout")
			}
		}
	}
}

func makeRefreshBEEFs(t *testing.T, srv *Server, addValidHeader bool) (string, []byte, []byte) {
	return makeRefreshBEEFsWithSatoshis(t, srv, addValidHeader, 1000)
}

func makeRefreshBEEFsWithSatoshis(t *testing.T, srv *Server, addValidHeader bool, satoshis uint64) (string, []byte, []byte) {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: satoshis, LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")})
	plain, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	unproven, err := plain.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatal(err)
	}

	isTrue := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: tx.TxID(), Txid: &isTrue},
		{Offset: 1, Hash: tx.TxID()},
	}}
	tx.MerklePath = transaction.NewMerklePath(1, path)
	provenBEEF, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	proven, err := provenBEEF.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatal(err)
	}
	if addValidHeader {
		prev, err := srv.headerStore.HashAtHeight(0)
		if err != nil {
			t.Fatal(err)
		}
		merkleRoot, err := tx.MerklePath.ComputeRoot(tx.TxID())
		if err != nil {
			t.Fatal(err)
		}
		root, err := chainhash.NewHashFromStr(merkleRoot.String())
		if err != nil {
			t.Fatal(err)
		}
		hdr := wire.NewBlockHeader(1, prev, root, 0x1d00ffff, 1)
		if err := srv.headerStore.AddHeaders(1, []*wire.BlockHeader{hdr}); err != nil {
			t.Fatal(err)
		}
	}
	return tx.TxID().String(), unproven, proven
}

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

func TestGetBEEFSubjectProofHeaderWithoutFetcherAndForProvenCache(t *testing.T) {
	for _, tc := range []struct {
		name        string
		withHeader  bool
		storeProven bool
		want        string
	}{
		{"unproven without fetcher", false, false, "false"},
		{"proven cache bypasses fetcher", true, true, "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServer(t)
			txid, unproven, proven := makeRefreshBEEFs(t, srv, tc.withHeader)
			cached := unproven
			if tc.storeProven {
				cached = proven
				srv.proofFetcher = &staticBEEFFetcher{beef: unproven}
			}
			if _, err := srv.proofStore.StoreBEEF(cached); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
			if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != tc.want {
				t.Fatalf("got %d %q, want header %q", w.Code, w.Header().Get("X-BEEF-Subject-Proven"), tc.want)
			}
			if f, ok := srv.proofFetcher.(*staticBEEFFetcher); ok && f.calls != 0 {
				t.Fatalf("already-proven cache triggered %d fetches", f.calls)
			}
		})
	}
}

func TestGetBEEFCacheHit(t *testing.T) {
	srv := testServer(t)

	// Build a minimal valid BEEF and store it in the proof store.
	// Create a coinbase-like tx with a merkle path so it serializes as BEEF.
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})

	// Create a trivial merkle path (height 1, leaf at index 0)
	isTrue := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: tx.TxID(), Txid: &isTrue},
		{Offset: 1, Hash: tx.TxID()},
	}}
	tx.MerklePath = transaction.NewMerklePath(900000, path)

	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("build beef: %v", err)
	}
	beefBytes, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("atomic bytes: %v", err)
	}

	txid, err := srv.proofStore.StoreBEEF(beefBytes)
	if err != nil {
		t.Fatalf("store beef: %v", err)
	}

	// Request it
	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["txid"] != txid {
		t.Fatalf("txid mismatch: got %v, want %s", resp["txid"], txid)
	}
	if resp["beef"] == nil || resp["beef"] == "" {
		t.Fatal("expected non-empty beef field")
	}
}

func TestGetBEEFCacheMiss404NoFetcher(t *testing.T) {
	// testServer has no ProofFetcher configured, so cache miss → 404
	srv := testServer(t)

	fakeTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	req := httptest.NewRequest("GET", "/tx/"+fakeTxid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown txid without fetcher, got %d", w.Code)
	}
}

func TestGetBEEFInvalidTxid(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/tx/tooshort/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short txid, got %d", w.Code)
	}
}

func TestGetBEEFBinaryResponse(t *testing.T) {
	srv := testServer(t)

	// Build and store BEEF (same as cache hit test)
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      2000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})
	isTrue := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: tx.TxID(), Txid: &isTrue},
		{Offset: 1, Hash: tx.TxID()},
	}}
	tx.MerklePath = transaction.NewMerklePath(900001, path)
	beef, _ := transaction.NewBeefFromTransaction(tx)
	beefBytes, _ := beef.AtomicBytes(tx.TxID())
	txid, _ := srv.proofStore.StoreBEEF(beefBytes)

	// Request as binary
	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	req.Header.Set("Accept", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("expected octet-stream content type, got %s", w.Header().Get("Content-Type"))
	}
	if len(w.Body.Bytes()) == 0 {
		t.Fatal("expected non-empty binary body")
	}
}

func testServerWithFetcher(t *testing.T, fetcher *spv.ProofFetcher) *Server {
	t.Helper()

	hdir, _ := os.MkdirTemp("", "anvil-beef-headers-*")
	t.Cleanup(func() { os.RemoveAll(hdir) })
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })

	pdir, _ := os.MkdirTemp("", "anvil-beef-proofs-*")
	t.Cleanup(func() { os.RemoveAll(pdir) })
	ps, err := spv.NewProofStore(pdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })

	edir, _ := os.MkdirTemp("", "anvil-beef-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })

	return NewServer(ServerConfig{
		HeaderStore:   hs,
		ProofStore:    ps,
		EnvelopeStore: es,
		Validator:     nil, // skip header validation in fetcher tests (no real headers)
		Broadcaster:   txrelay.NewBroadcaster(txrelay.NewMempool(), nil, slog.Default()),
		AuthToken:     "test-token",
		Logger:        slog.Default(),
		ProofFetcher:  fetcher,
	})
}

// buildTestBeefTx creates a minimal tx with a merkle path and returns its
// raw hex, txid, and the TSC proof JSON that a mock WoC would return.
func buildTestBeefTx(t *testing.T) (rawHex string, txid string, tscJSON string, blockHeight int) {
	t.Helper()
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      5000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})

	txid = tx.TxID().String()
	rawHex = hex.EncodeToString(tx.Bytes())
	blockHeight = 900100

	// Build a trivial TSC proof: the tx is the only leaf
	// TSC format: [{index, txOrId, target, nodes: ["*"]}]
	tscJSON = fmt.Sprintf(`[{"index":0,"txOrId":"%s","target":"","nodes":["*"]}]`, txid)
	return
}

func TestGetBEEFFetcherEnabledCacheMiss(t *testing.T) {
	rawHex, txid, tscJSON, blockHeight := buildTestBeefTx(t)

	// Mock WoC server
	mockWoC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/hex"):
			w.Write([]byte(rawHex))
		case strings.HasSuffix(r.URL.Path, "/proof/tsc"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(tscJSON))
		default:
			// tx info endpoint
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"blockheight":%d}`, blockHeight)
		}
	}))
	defer mockWoC.Close()

	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mockWoC.URL)

	srv := testServerWithFetcher(t, fetcher)

	// First request: cache miss → fetcher builds BEEF
	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for fetcher-enabled cache miss, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["txid"] != txid {
		t.Fatalf("txid mismatch: got %v, want %s", resp["txid"], txid)
	}
	if resp["beef"] == nil || resp["beef"] == "" {
		t.Fatal("expected non-empty beef in response")
	}

	// Second request: should be a cache hit now (proof was stored)
	if !srv.proofStore.HasBEEF(txid) {
		t.Fatal("expected BEEF to be cached in proof store after fetch")
	}
}

// TestGetBEEFSourceField verifies the source field lets consumers distinguish
// overlay-cached BEEF from passthrough. Wallet multi-source BEEF chains need
// this to know whether Anvil handled the tx natively or is relaying an
// external indexer (in which case the wallet should prefer a direct upstream).
func TestGetBEEFSourceFieldCacheHit(t *testing.T) {
	srv := testServer(t)

	// Store a BEEF (same setup as TestGetBEEFCacheHit)
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})
	isTrue := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: tx.TxID(), Txid: &isTrue},
		{Offset: 1, Hash: tx.TxID()},
	}}
	tx.MerklePath = transaction.NewMerklePath(900002, path)
	beef, _ := transaction.NewBeefFromTransaction(tx)
	beefBytes, _ := beef.AtomicBytes(tx.TxID())
	txid, _ := srv.proofStore.StoreBEEF(beefBytes)

	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["source"] != "cached" {
		t.Fatalf("expected source=cached for ProofStore hit, got %v", resp["source"])
	}
}

func TestGetBEEFSourceFieldUpstreamFetch(t *testing.T) {
	rawHex, txid, tscJSON, blockHeight := buildTestBeefTx(t)

	mockWoC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/hex"):
			w.Write([]byte(rawHex))
		case strings.HasSuffix(r.URL.Path, "/proof/tsc"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(tscJSON))
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"blockheight":%d}`, blockHeight)
		}
	}))
	defer mockWoC.Close()

	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mockWoC.URL)
	srv := testServerWithFetcher(t, fetcher)

	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	// Fetcher has no ARC client configured, so merkle proof must come from WoC
	if resp["source"] != "woc" {
		t.Fatalf("expected source=woc for WoC-supplied proof, got %v", resp["source"])
	}
}

func TestGetBEEFSourceHeaderOnBinaryResponse(t *testing.T) {
	srv := testServer(t)

	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      3000,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})
	isTrue := true
	path := [][]*transaction.PathElement{{
		{Offset: 0, Hash: tx.TxID(), Txid: &isTrue},
		{Offset: 1, Hash: tx.TxID()},
	}}
	tx.MerklePath = transaction.NewMerklePath(900003, path)
	beef, _ := transaction.NewBeefFromTransaction(tx)
	beefBytes, _ := beef.AtomicBytes(tx.TxID())
	txid, _ := srv.proofStore.StoreBEEF(beefBytes)

	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	req.Header.Set("Accept", "application/octet-stream")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-BEEF-Source"); got != "cached" {
		t.Fatalf("expected X-BEEF-Source=cached header on binary response, got %q", got)
	}
}

func TestGetBEEFFetcherUnconfirmed404(t *testing.T) {
	rawHex, txid, _, _ := buildTestBeefTx(t)

	// Mock WoC: tx exists but is unconfirmed (blockheight = 0)
	mockWoC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/hex"):
			w.Write([]byte(rawHex))
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"blockheight":0}`)
		}
	}))
	defer mockWoC.Close()

	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mockWoC.URL)

	srv := testServerWithFetcher(t, fetcher)

	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unconfirmed tx, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetBEEFFetcherTxNotFound404(t *testing.T) {
	// Mock WoC: tx doesn't exist
	mockWoC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer mockWoC.Close()

	fetcher := spv.NewProofFetcher(nil, slog.Default())
	fetcher.SetBaseURL(mockWoC.URL)

	srv := testServerWithFetcher(t, fetcher)

	fakeTxid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	req := httptest.NewRequest("GET", "/tx/"+fakeTxid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent tx, got %d: %s", w.Code, w.Body.String())
	}
}

func mustDecodeScript(t *testing.T, h string) *bsvscript.Script {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	s := bsvscript.Script(b)
	return &s
}
