package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestRegisteredGatewayDomainIsConfinedToItsTXTOrigin(t *testing.T) {
	dir := t.TempDir()
	operatorPath := filepath.Join(dir, "sites.conf")
	registrationsPath := filepath.Join(dir, "gateway-registrations.conf")
	registrar := NewRegistrar(operatorPath, registrationsPath, "api.example", nil, slog.Default())
	for _, domain := range []string{"one.example", "two.example"} {
		if status, code, err := registrar.register(registrationIdentity('1'), domain); err != nil || status != http.StatusCreated || code != "" {
			t.Fatalf("register %s = (%d, %q, %v)", domain, status, code, err)
		}
	}

	one := testOutpoint(920, 0)
	two := testOutpoint(921, 0)
	resolver := NewResolver(ResolverConfig{})
	resolver.lookup = hostTXT{"one.example": one, "two.example": two}
	policy := NewPolicy(NewAllowlistWithRegistrations(operatorPath, registrationsPath, "api.example", slog.Default()), resolver)
	content := newGraphContent()
	content.set(one, "site one")
	content.set(two, "site two")
	router := &Router{
		API:     stubAPIHandler(),
		Sites:   NewSiteHandler(SiteHandlerConfig{Policy: policy, Content: content, ContentScope: "site"}),
		APIHost: "api.example",
	}

	assertGatewayResponse(t, router, "one.example", "/", http.StatusOK, "site one")
	assertGatewayResponse(t, router, "two.example", "/", http.StatusOK, "site two")
	assertGatewayResponse(t, router, "one.example", "/status", http.StatusNotFound, "")
	assertGatewayResponse(t, router, "one.example", "/data?topic=release:private", http.StatusNotFound, "")
	assertGatewayResponse(t, router, "one.example", "/content/"+two, http.StatusNotFound, "")
	assertGatewayResponse(t, router, "one.example", "/inbox/anything", http.StatusNotFound, "")
}

func assertGatewayResponse(t *testing.T, handler http.Handler, host, path string, status int, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != status {
		t.Fatalf("%s%s = %d, want %d: %s", host, path, w.Code, status, w.Body.String())
	}
	if status == http.StatusOK && w.Body.String() != body {
		t.Fatalf("%s%s body = %q, want %q", host, path, w.Body.String(), body)
	}
	if host != "api.example" && w.Body.String() == "API" {
		t.Fatalf("site request %s%s reached API", host, path)
	}
}
