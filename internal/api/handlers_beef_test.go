package api

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

// This file holds the shared test doubles and helpers GET /tx/{txid}/beef's
// other test files draw on (handlers_beef_refresh_test.go,
// handlers_beef_fetcher_test.go, and this package's other BEEF-related test
// files), plus the route's basic cache-hit/miss and malformed-stored-BEEF
// behavior, which needs none of the refresh or fetcher machinery itself.
// Split from one 876-line file with no behavior change (bu_b4_specs.md item
// 7); every test below is unchanged from before the split.

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

func mustDecodeScript(t *testing.T, h string) *bsvscript.Script {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	s := bsvscript.Script(b)
	return &s
}

// beefEntriesV2 writes a V2 BEEF of bumps and already-encoded entries, in
// order -- the hand-rolled construction beefnorm's own tests use
// (TestParse_RefusesATxidHeldTwice), needed here because go-sdk's structured
// transaction.Beef type cannot represent two entries naming the same txid:
// its Transactions field is a map, so building one through the SDK always
// collapses a duplicate before it ever reaches beefnorm.
func beefEntriesV2(bumps []*transaction.MerklePath, es ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, transaction.BEEF_V2)
	b = append(b, util.VarInt(len(bumps)).Bytes()...)
	for _, p := range bumps {
		b = append(b, p.Bytes()...)
	}
	b = append(b, util.VarInt(len(es)).Bytes()...)
	for _, e := range es {
		b = append(b, e...)
	}
	return b
}

// beefRawEntry is a V2 BEEF entry holding tx's raw bytes with no BUMP index.
func beefRawEntry(tx *transaction.Transaction) []byte { return append([]byte{0}, tx.Bytes()...) }

// beefAtomic wraps inner (a V2 BEEF) in an Atomic BEEF header naming subject,
// unchecked, as ts-sdk's toBinaryAtomic does. go-sdk's NewTransactionFromBEEF
// (what ProofStore.StoreBEEF parses with) refuses a bare V2 BEEF outright
// ("use NewBeefFromBytes..."), so a stored BEEF needs this wrapper to be
// realistic.
func beefAtomic(subject *transaction.Transaction, inner []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, transaction.ATOMIC_BEEF)
	out = append(out, subject.TxID()[:]...)
	return append(out, inner...)
}

// TestGetBEEFRefusedStoredBEEFServesEmptyConfidence: an old Atomic BEEF whose
// inner V2 BEEF holds one txid twice. go-sdk's own, more lenient reader
// (transaction.NewTransactionFromBEEF, what ProofStore.StoreBEEF parses with
// to find the storage key) collapses the duplicate into one map entry and
// accepts it without complaint, so this node could have stored it;
// beefnorm's stricter normalizer (what Validator.ValidateBEEF revalidates
// with) refuses it, the same shape TestParse_RefusesATxidHeldTwice
// (internal/beefnorm) proves is refused. Getting it back from
// GET /tx/{txid}/beef must not report "confidence":"invalid": that word
// means a FRESH submission is refused right now, not that an already-served
// historical payment was bad (cold review round 4's NITs, C4.3,
// handlers_beef.go:85-100).
func TestGetBEEFRefusedStoredBEEFServesEmptyConfidence(t *testing.T) {
	srv := testServer(t)

	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1500,
		LockingScript: mustDecodeScript(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"),
	})
	refused := beefAtomic(tx, beefEntriesV2(nil, beefRawEntry(tx), beefRawEntry(tx)))

	// Pin down exactly what is being tested before going through HTTP: the
	// normalizer refuses this BEEF, and Confidence stays ConfidenceInvalid
	// (unchanged for every other caller) while Refused is the new signal.
	result, err := srv.validator.ValidateBEEF(context.Background(), refused)
	if err != nil {
		t.Fatalf("ValidateBEEF returned an error (should be nil, state lives in Result): %v", err)
	}
	if !result.Refused || result.Confidence != spv.ConfidenceInvalid {
		t.Fatalf("got Refused=%v Confidence=%q, want Refused=true and Confidence=%q unchanged",
			result.Refused, result.Confidence, spv.ConfidenceInvalid)
	}

	txid, err := srv.proofStore.StoreBEEF(refused)
	if err != nil {
		t.Fatalf("go-sdk's lenient parse (ProofStore.StoreBEEF) refused a BEEF it should accept: %v", err)
	}

	req := httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for a cached BEEF even when its revalidation is refused, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if conf, present := resp["confidence"]; present {
		t.Fatalf(`confidence = %v, want the field omitted: a refused revalidation must not read back as "invalid"`, conf)
	}
}
