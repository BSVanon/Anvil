package api

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/spv"
)

func TestGetBEEFCacheMissRejectsMismatchedSubject(t *testing.T) {
	srv := testServer(t)
	fetchedTxID, _, fetched := makeRefreshBEEFsWithSatoshis(t, srv, false, 1000)
	requestedTxID, _, _ := makeRefreshBEEFsWithSatoshis(t, srv, false, 1001)
	srv.proofFetcher = &staticBEEFFetcher{beef: fetched, source: spv.BEEFSourceWoC}

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tx/"+requestedTxID+"/beef", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	body, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "fetched proof subject does not match txid") {
		t.Fatalf("body = %s", body)
	}
	if _, err := srv.proofStore.GetBEEF(fetchedTxID); err == nil {
		t.Fatal("mismatched fetched BEEF was stored")
	}
}

func TestGetBEEFRefreshRejectsMismatchedSubject(t *testing.T) {
	srv := testServer(t)
	fetchedTxID, _, fetched := makeRefreshBEEFsWithSatoshis(t, srv, true, 1000)
	requestedTxID, cached, _ := makeRefreshBEEFsWithSatoshis(t, srv, false, 1001)
	if _, err := srv.proofStore.StoreBEEF(cached); err != nil {
		t.Fatal(err)
	}
	srv.proofFetcher = &staticBEEFFetcher{beef: fetched, source: spv.BEEFSourceWoC}

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tx/"+requestedTxID+"/beef", nil))
	if w.Code != http.StatusOK || w.Header().Get("X-BEEF-Subject-Proven") != "false" {
		t.Fatalf("cached response = %d, proven=%q", w.Code, w.Header().Get("X-BEEF-Subject-Proven"))
	}
	if !strings.Contains(w.Body.String(), hex.EncodeToString(cached)) {
		t.Fatal("refresh did not serve the cached copy")
	}
	stored, err := srv.proofStore.GetBEEF(requestedTxID)
	if err != nil || string(stored) != string(cached) {
		t.Fatalf("requested cache changed: %v", err)
	}
	if _, err := srv.proofStore.GetBEEF(fetchedTxID); err == nil {
		t.Fatal("mismatched refreshed BEEF was stored")
	}
}
