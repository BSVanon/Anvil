package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCredentialDependentReadsAreNotCacheable(t *testing.T) {
	srv := testServer(t)
	storePrivate(t, srv, `{"secret":"cache-sensitive"}`)

	paths := []string{
		"/data?topic=app:private-x",
		"/topics",
		"/topics/app:private-x",
		"/identity/0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		"/stats",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("X-Anvil-Auth", "test-token")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
				t.Fatalf("Cache-Control = %q, want private, no-store", got)
			}
			vary := strings.Join(w.Header().Values("Vary"), ",")
			for _, credential := range []string{"Authorization", "X-Anvil-Auth"} {
				if !headerListContains(vary, credential) {
					t.Fatalf("Vary = %q, want %s", vary, credential)
				}
			}
		})
	}
}

func headerListContains(value, name string) bool {
	for _, field := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(field), name) {
			return true
		}
	}
	return false
}
