package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/syndtr/goleveldb/leveldb"
)

type panickingBEEFFetcher struct{ calls int }

func (f *panickingBEEFFetcher) FetchBEEF(string) ([]byte, string, error) {
	f.calls++
	panic("fetch panic")
}

func (f *panickingBEEFFetcher) TxStatus(string) (*spv.TxStatusResult, error) {
	return nil, errors.New("not used by BEEF refresh tests")
}

func TestGetBEEFRefreshPanicAndMalformedFetchServeCachedCopy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fetcher func() beefFetcher
	}{
		{name: "panicking fetcher", fetcher: func() beefFetcher { return &panickingBEEFFetcher{} }},
		{name: "malformed BEEF", fetcher: func() beefFetcher {
			return &staticBEEFFetcher{beef: []byte{1, 1, 1, 1}, source: spv.BEEFSourceWoC}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServer(t)
			txid, cached, _ := makeRefreshBEEFs(t, srv, false)
			if _, err := srv.proofStore.StoreBEEF(cached); err != nil {
				t.Fatal(err)
			}
			srv.proofFetcher = tc.fetcher()
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
			if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "false" {
				t.Fatalf("cached fallback = %d %q: %s", w.Code, w.Header().Get("X-BEEF-Subject-Proven"), w.Body.String())
			}
			var response map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["beef"] != hex.EncodeToString(cached) {
				t.Fatal("refresh failure did not serve the cached copy")
			}
			eventually(t, time.Second, func() bool { return len(srv.proofRefreshSlots) == 0 })
		})
	}
}

func TestGetBEEFMalformedCachedBytesAreServedWithoutPanic(t *testing.T) {
	txid := strings.Repeat("0", 64)
	malformed := []byte{1, 1, 1, 1}
	proofDir := t.TempDir()
	db, err := leveldb.OpenFile(proofDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put([]byte("beef:"+txid), malformed, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	proofStore, err := spv.NewProofStore(proofDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proofStore.Close() })
	srv := NewServer(ServerConfig{ProofStore: proofStore, Logger: slog.Default()})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/tx/"+txid+"/beef", nil))
	if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "false" {
		t.Fatalf("malformed cache response = %d %q: %s", w.Code, w.Header().Get("X-BEEF-Subject-Proven"), w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["beef"] != hex.EncodeToString(malformed) {
		t.Fatalf("served BEEF = %v", response["beef"])
	}
}
