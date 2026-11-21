package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookupCursorHeadersAreAvailableToBrowsers(t *testing.T) {
	handler := cors(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodOptions, "/lookup", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "X-Overlay-Cursor") {
		t.Fatal("lookup cursor request header is not allowed")
	}
	exposed := rec.Header().Get("Access-Control-Expose-Headers")
	for _, name := range []string{"X-Overlay-Truncated", "X-Overlay-Cursor", "X-Overlay-Omitted"} {
		if !strings.Contains(exposed, name) {
			t.Fatalf("response header %s is not exposed", name)
		}
	}
}
