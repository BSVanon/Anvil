package legacyshim

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func queryReq() (*http.Request, *httptest.ResponseRecorder) {
	body, _ := json.Marshal(map[string]any{
		"service": "ls_users",
		"query":   map[string]any{"presentationHash": "abcd"},
	})
	req := httptest.NewRequest("POST", "/overlay/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req, httptest.NewRecorder()
}

// TestQuery_EmitsSyncHeaders: when SyncStatus is wired, /overlay/query stamps the
// X-Overlay-* readiness headers so a caller can gate on them atomically with the
// answer. (scriptedEngine.Lookup returns an empty answer → HTTP 200.)
func TestQuery_EmitsSyncHeaders(t *testing.T) {
	shim := &Shim{
		Engine:        &scriptedEngine{},
		Parsers:       DefaultParsers(),
		ServiceTopics: DefaultServiceTopics(),
		SyncStatus: func() OverlaySyncStatus {
			return OverlaySyncStatus{
				GASPEnabled:      true,
				GASPInitialDone:  true,
				GASPLastSyncUnix: 1700000000,
				GASPIntervalSecs: 1800,
			}
		},
	}

	req, w := queryReq()
	shim.Query(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	h := w.Header()
	for k, want := range map[string]string{
		"X-Overlay-Gasp-Enabled":           "true",
		"X-Overlay-Gasp-Initial-Sync-Done": "true",
		"X-Overlay-Gasp-Interval-Secs":     "1800",
		"X-Overlay-Gasp-Last-Sync-Unix":    "1700000000",
	} {
		if got := h.Get(k); got != want {
			t.Fatalf("header %s = %q, want %q", k, got, want)
		}
	}
}

// TestQuery_OmitsLastSyncWhenNeverSynced: a node that has never completed a sync
// must not emit a Last-Sync stamp (0 → omitted), and must report the cold state
// honestly so the caller does NOT treat an empty answer as authoritative.
func TestQuery_OmitsLastSyncWhenNeverSynced(t *testing.T) {
	shim := &Shim{
		Engine:        &scriptedEngine{},
		Parsers:       DefaultParsers(),
		ServiceTopics: DefaultServiceTopics(),
		SyncStatus: func() OverlaySyncStatus {
			return OverlaySyncStatus{GASPEnabled: true, GASPInitialDone: false, GASPIntervalSecs: 1800}
		},
	}
	req, w := queryReq()
	shim.Query(w, req)

	if got := w.Header().Get("X-Overlay-Gasp-Initial-Sync-Done"); got != "false" {
		t.Fatalf("cold node must report initial-sync-done=false, got %q", got)
	}
	if got := w.Header().Get("X-Overlay-Gasp-Last-Sync-Unix"); got != "" {
		t.Fatalf("never-synced node must omit last-sync header, got %q", got)
	}
}

// TestQuery_NoHeadersWhenSyncStatusUnset: unchanged legacy behaviour when the
// readiness accessor isn't wired.
func TestQuery_NoHeadersWhenSyncStatusUnset(t *testing.T) {
	shim := &Shim{Engine: &scriptedEngine{}, Parsers: DefaultParsers(), ServiceTopics: DefaultServiceTopics()}
	req, w := queryReq()
	shim.Query(w, req)
	if got := w.Header().Get("X-Overlay-Gasp-Enabled"); got != "" {
		t.Fatalf("no readiness headers expected when SyncStatus unset, got %q", got)
	}
}
