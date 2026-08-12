package v3engine

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/gaspstatus"
)

// newTestServerWithSync wires the canonical handlers with a fixed GASP
// readiness snapshot, so a /lookup response can be asserted for its
// X-Overlay-Gasp-* headers.
func newTestServerWithSync(t *testing.T, snap gaspstatus.Snapshot) string {
	t.Helper()
	eng, _ := newTestEngine(t)
	h := NewHandlers(eng)
	h.SyncStatus = func() gaspstatus.Snapshot { return snap }
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func postLookup(t *testing.T, url string) *http.Response {
	t.Helper()
	// Any query works — the readiness headers ride on every response. A
	// well-formed but unknown-service query keeps the test independent of
	// seeded state.
	body, _ := json.Marshal(map[string]any{"service": "ls_unknown", "query": map[string]any{"x": 1}})
	resp, err := http.Post(url+"/lookup", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /lookup: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestLookupHandler_ReadinessHeaders pins the contract: the canonical
// POST /lookup carries the same X-Overlay-Gasp-* readiness headers the
// legacy /overlay/query emits, so a caller can bind an answer's trust to
// this node's sync-state.
func TestLookupHandler_ReadinessHeaders(t *testing.T) {
	url := newTestServerWithSync(t, gaspstatus.Snapshot{
		Enabled:         true,
		InitialSyncDone: true,
		LastSyncUnix:    1750000000,
		IntervalSecs:    300,
	})
	resp := postLookup(t, url)

	want := map[string]string{
		"X-Overlay-Gasp-Enabled":           "true",
		"X-Overlay-Gasp-Initial-Sync-Done": "true",
		"X-Overlay-Gasp-Interval-Secs":     "300",
		"X-Overlay-Gasp-Last-Sync-Unix":    "1750000000",
	}
	for h, exp := range want {
		if got := resp.Header.Get(h); got != exp {
			t.Fatalf("header %s = %q, want %q", h, got, exp)
		}
	}
}

// TestLookupHandler_ReadinessNeverSyncedOmitsLastSync mirrors the legacy
// behavior: a node that has never completed a sync omits Last-Sync-Unix
// (rather than emitting 0), while still reporting enabled/initial state.
func TestLookupHandler_ReadinessNeverSyncedOmitsLastSync(t *testing.T) {
	url := newTestServerWithSync(t, gaspstatus.Snapshot{
		Enabled:         true,
		InitialSyncDone: false,
		LastSyncUnix:    0,
		IntervalSecs:    1800,
	})
	resp := postLookup(t, url)

	if got := resp.Header.Get("X-Overlay-Gasp-Enabled"); got != "true" {
		t.Fatalf("Enabled = %q, want true", got)
	}
	if got := resp.Header.Get("X-Overlay-Gasp-Initial-Sync-Done"); got != "false" {
		t.Fatalf("Initial-Sync-Done = %q, want false", got)
	}
	if got := resp.Header.Get("X-Overlay-Gasp-Last-Sync-Unix"); got != "" {
		t.Fatalf("Last-Sync-Unix should be omitted when never synced, got %q", got)
	}
}

// TestLookupHandler_NoReadinessHeadersWhenUnset confirms the headers are
// absent when no SyncStatus is wired (single-node / unwired builds), so
// nothing lies about sync state.
func TestLookupHandler_NoReadinessHeadersWhenUnset(t *testing.T) {
	url := newTestServer(t) // NewHandlers(eng) with no SyncStatus
	resp := postLookup(t, url)
	for _, h := range []string{
		"X-Overlay-Gasp-Enabled",
		"X-Overlay-Gasp-Initial-Sync-Done",
		"X-Overlay-Gasp-Interval-Secs",
		"X-Overlay-Gasp-Last-Sync-Unix",
	} {
		if got := resp.Header.Get(h); got != "" {
			t.Fatalf("header %s should be absent when SyncStatus unset, got %q", h, got)
		}
	}
}
