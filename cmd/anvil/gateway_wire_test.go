package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/gateway"
	"github.com/BSVanon/Anvil/internal/headers"
)

// newTestAPIServer builds a minimal but functional *api.Server: a real
// (temp-dir, PoW-skipping) HeaderStore so GET /stats — which reads the
// header tip unconditionally — works, with everything else left at its
// zero value.
func newTestAPIServer(t *testing.T) *api.Server {
	t.Helper()
	hs, err := headers.NewTestStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hs.Close() })
	return api.NewServer(api.ServerConfig{HeaderStore: hs})
}

// TestWireGateway_DisabledIsIdenticalToTodaysHandler is the hard gate's
// "[gateway] off must be byte-for-byte identical to today's behaviour":
// wireGateway's disabled path must behave exactly like calling
// srv.Handler() directly — the same mux, the same header strip, nothing
// else in between.
func TestWireGateway_DisabledIsIdenticalToTodaysHandler(t *testing.T) {
	cfg := &config.Config{} // Gateway.Enabled is false by default
	srv := newTestAPIServer(t)
	logger := slog.Default()

	wired := wireGateway(cfg, srv, logger, nil)
	today := srv.Handler()

	for _, path := range []string{"/stats", "/no-such-route-at-all"} {
		req1 := httptest.NewRequest("GET", "http://example.org"+path, nil)
		w1 := httptest.NewRecorder()
		wired.ServeHTTP(w1, req1)

		req2 := httptest.NewRequest("GET", "http://example.org"+path, nil)
		w2 := httptest.NewRecorder()
		today.ServeHTTP(w2, req2)

		if w1.Code != w2.Code {
			t.Fatalf("%s: status differs: wireGateway=%d, srv.Handler()=%d", path, w1.Code, w2.Code)
		}
		if w1.Body.String() != w2.Body.String() {
			t.Fatalf("%s: body differs:\nwireGateway: %s\nsrv.Handler(): %s", path, w1.Body.String(), w2.Body.String())
		}
		h1, h2 := w1.Header(), w2.Header()
		if len(h1) != len(h2) {
			t.Fatalf("%s: header set differs: wireGateway=%v, srv.Handler()=%v", path, h1, h2)
		}
		for k, v := range h1 {
			if got := h2[k]; len(got) != len(v) || (len(got) > 0 && got[0] != v[0]) {
				t.Fatalf("%s: header %q differs: wireGateway=%v, srv.Handler()=%v", path, k, v, got)
			}
		}
	}
}

// TestWireGateway_EnabledBuildsRouterAndWiresStats is the gateway-on smoke
// test: with [gateway] enabled, wireGateway must return a *gateway.Router
// configured from cfg, with the SetGatewayStats hook actually wired (the
// gateway counters must show up in GET /stats reached through api_host).
func TestWireGateway_EnabledBuildsRouterAndWiresStats(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	cfg.Gateway.APIHost = "admin.example.org"
	cfg.Gateway.SitesFile = filepath.Join(dir, "gateway-sites.conf") // missing file: not an error
	cfg.Gateway.ContentScope = "site"
	cfg.Node.DataDir = dir
	// Built directly rather than through config.Load, so none of
	// finalizeGateway's defaulting runs: an explicit, non-privileged,
	// ephemeral bind address here keeps wireGateway's new TLS/plain
	// listeners (started because Gateway.Enabled is true) off a real
	// privileged port for the lifetime of this test.
	cfg.Gateway.HTTPSListen = "127.0.0.1:0"
	cfg.Gateway.HTTPListen = "127.0.0.1:0"

	srv := newTestAPIServer(t)
	logger := slog.Default()

	h := wireGateway(cfg, srv, logger, nil)
	rt, ok := h.(*gateway.Router)
	if !ok {
		t.Fatalf("expected wireGateway to return a *gateway.Router when enabled, got %T", h)
	}
	if rt.APIHost != cfg.Gateway.APIHost {
		t.Fatalf("expected APIHost %q to be wired through, got %q", cfg.Gateway.APIHost, rt.APIHost)
	}
	if rt.Sites == nil {
		t.Fatal("expected a non-nil Sites handler")
	}

	// api_host still reaches /stats — now carrying the gateway
	// counters, proving SetGatewayStats was actually wired (not just that
	// the Router exists).
	req := httptest.NewRequest("GET", "http://admin.example.org/stats", nil)
	req.Host = "admin.example.org"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var body map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode /stats: %v", err)
	}
	gw, ok := body["gateway"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected a \"gateway\" object in /stats once gateway mode is wired, got %#v", body["gateway"])
	}
	for _, key := range []string{
		"gateway_requests", "gateway_not_found", "gateway_txt_lookups",
		"gateway_txt_stale_served", "gateway_scope_refused",
	} {
		if _, ok := gw[key]; !ok {
			t.Fatalf("expected %q in the gateway stats, got %#v", key, gw)
		}
	}

	// A Host that is neither api_host nor an allowed site: 404.
	req2 := httptest.NewRequest("GET", "http://not-a-site.example.org/", nil)
	req2.Host = "not-a-site.example.org"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unrecognised Host, got %d", w2.Code)
	}
}

// TestWireGateway_DisabledStartsNoListeners is the hard constraint's
// wiring-level proof: with [gateway] off, wireGateway must return before
// ever reaching startGatewayTLS — nothing binds the configured gateway
// addresses, whatever they're set to. Paired with
// TestWireGateway_EnabledStartsListeners below, which binds the same
// kind of address when enabled, so this isn't vacuously true because
// nothing ever binds regardless.
func TestWireGateway_DisabledStartsNoListeners(t *testing.T) {
	const httpsAddr = "127.0.0.1:48443"
	const httpAddr = "127.0.0.1:48080"

	cfg := &config.Config{} // Gateway.Enabled is false by default
	cfg.Gateway.HTTPSListen = httpsAddr
	cfg.Gateway.HTTPListen = httpAddr

	srv := newTestAPIServer(t)
	_ = wireGateway(cfg, srv, slog.Default(), nil)

	// wireGateway's disabled path is a single synchronous early return —
	// nothing async to wait for — but this sleep is cheap defense against
	// a future refactor that moves a bind off the calling goroutine
	// without this test noticing.
	time.Sleep(50 * time.Millisecond)

	for _, addr := range []string{httpsAddr, httpAddr} {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Fatalf("something is listening on %s although [gateway] is disabled", addr)
		}
	}
}

// TestWireGateway_EnabledStartsListeners is
// TestWireGateway_DisabledStartsNoListeners's positive counterpart: with
// [gateway] on, both the https and the plain listener actually come up.
func TestWireGateway_EnabledStartsListeners(t *testing.T) {
	const httpsAddr = "127.0.0.1:48444"
	const httpAddr = "127.0.0.1:48081"
	dir := t.TempDir()

	cfg := &config.Config{}
	cfg.Gateway.Enabled = true
	cfg.Gateway.APIHost = "admin.example.org"
	cfg.Gateway.SitesFile = filepath.Join(dir, "gateway-sites.conf")
	cfg.Gateway.ContentScope = "site"
	cfg.Node.DataDir = dir
	cfg.Gateway.HTTPSListen = httpsAddr
	cfg.Gateway.HTTPListen = httpAddr

	srv := newTestAPIServer(t)
	_ = wireGateway(cfg, srv, slog.Default(), nil)

	deadline := time.Now().Add(2 * time.Second)
	for _, addr := range []string{httpsAddr, httpAddr} {
		var lastErr error
		for time.Now().Before(deadline) {
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				lastErr = nil
				break
			}
			lastErr = err
			time.Sleep(20 * time.Millisecond)
		}
		if lastErr != nil {
			t.Fatalf("nothing is listening on %s although [gateway] is enabled: %v", addr, lastErr)
		}
	}
}
