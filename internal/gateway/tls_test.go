package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ── HostPolicy ──

func TestHostPolicy_AllowedHostPasses(t *testing.T) {
	origin := testOutpoint(61, 0)
	fake := &fakeTXTLookup{records: []string{"ordfs=" + origin}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	hp := newHostPolicy(p, "", ensureCounters(nil))

	if err := hp(context.Background(), "allowed.example.org"); err != nil {
		t.Fatalf("HostPolicy refused an allowed host: %v", err)
	}
}

// TestHostPolicy_UnknownHostRefusedWithoutACMECall confirms an unknown
// host is refused without any ACME call, by counting the outbound
// calls: the sites file lists a domain
// but no "origin" entries, so Policy.Allowed's own short-circuit
// (policy.go) never reaches the resolver at all for an unlisted host —
// fake.callCount() stays 0, proving no network call (DNS, let alone
// ACME) was made before the refusal.
func TestHostPolicy_UnknownHostRefusedWithoutACMECall(t *testing.T) {
	fake := &fakeTXTLookup{}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	counters := ensureCounters(nil)
	hp := newHostPolicy(p, "", counters)

	err := hp(context.Background(), "unknown.example")
	if err == nil {
		t.Fatal("HostPolicy allowed an unknown host")
	}
	if !errors.Is(err, errHostNotAllowed) {
		t.Fatalf("error = %v, want errHostNotAllowed", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("fake TXT resolver was called %d times for an unlisted host, want 0", fake.callCount())
	}
	if got := counters.ACMERefusedHost.Load(); got != 1 {
		t.Fatalf("ACMERefusedHost = %d, want 1", got)
	}
}

func TestHostPolicy_RefusesLoopbackHost(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(62, 0)}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	hp := newHostPolicy(p, "", ensureCounters(nil))

	for _, host := range []string{"localhost", "127.0.0.1", "127.5.5.5", "::1"} {
		if err := hp(context.Background(), host); err == nil {
			t.Errorf("HostPolicy issued a certificate decision of nil (allowed) for loopback host %q", host)
		} else if !errors.Is(err, errHostNotAllowed) {
			t.Errorf("host %q: error = %v, want errHostNotAllowed", host, err)
		}
	}
}

func TestHostPolicy_RefusesIPLiteral(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(63, 0)}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	hp := newHostPolicy(p, "", ensureCounters(nil))

	for _, host := range []string{"93.184.216.34", "2001:db8::1"} {
		if err := hp(context.Background(), host); err == nil {
			t.Errorf("HostPolicy allowed an IP literal %q", host)
		} else if !errors.Is(err, errHostNotAllowed) {
			t.Errorf("host %q: error = %v, want errHostNotAllowed", host, err)
		}
	}
}

func TestHostPolicy_AllowsAPIHost(t *testing.T) {
	fake := &fakeTXTLookup{}
	p, _, _ := newTestPolicy(t, "", fake)
	hp := newHostPolicy(p, "admin.example.org", ensureCounters(nil))

	if err := hp(context.Background(), "admin.example.org"); err != nil {
		t.Fatalf("HostPolicy refused api_host: %v", err)
	}
	if err := hp(context.Background(), "ADMIN.EXAMPLE.ORG."); err != nil {
		t.Fatalf("HostPolicy refused api_host in a different case/trailing dot: %v", err)
	}
}

// TestNewACMEManager_RefusesUnallowedHostWithoutACMECall is the
// integration-level counterpart to
// TestHostPolicy_UnknownHostRefusedWithoutACMECall: it goes through the
// real autocert.Manager NewACMEManager builds (not newHostPolicy directly),
// proving the HostPolicy that function returns is actually wired onto the
// Manager it configures. A change that dropped the HostPolicy field from
// that Manager literal would leave autocert's own default in its place —
// which allows every host — so GetCertificate would instead proceed to
// contact the ACME directory below, and this test would catch that by
// counting its hits.
func TestNewACMEManager_RefusesUnallowedHostWithoutACMECall(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	fake := &fakeTXTLookup{}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{
		Cache: cache, Policy: p, Directory: ts.URL, AcceptTOS: true,
	})

	_, err := manager.GetCertificate(&tls.ClientHelloInfo{
		ServerName:   "unknown.example",
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	if err == nil {
		t.Fatal("GetCertificate succeeded for a host HostPolicy should have refused")
	}
	if !errors.Is(err, errHostNotAllowed) {
		t.Fatalf("error = %v, want errHostNotAllowed (a different error means HostPolicy did not refuse this host before something else failed)", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("the fake ACME directory was hit %d times for a host HostPolicy should refuse, want 0", got)
	}
}

// ── Timeouts (overseer amendment) ──

func TestNewHTTPSServer_Timeouts(t *testing.T) {
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache})
	srv := NewHTTPSServer(":0", http.NotFoundHandler(), manager, nil)
	if srv.ReadHeaderTimeout != gatewayReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, gatewayReadHeaderTimeout)
	}
	if srv.IdleTimeout != gatewayIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, gatewayIdleTimeout)
	}
	if srv.WriteTimeout != 10*time.Minute {
		t.Errorf("WriteTimeout = %v, want 10m", srv.WriteTimeout)
	}
}

func TestNewHTTPServer_Timeouts(t *testing.T) {
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache})
	srv := NewHTTPServer(":0", manager, nil, "")
	if srv.ReadHeaderTimeout != gatewayReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, gatewayReadHeaderTimeout)
	}
	if srv.IdleTimeout != gatewayIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, gatewayIdleTimeout)
	}
	if srv.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want 60s", srv.WriteTimeout)
	}
}

// TestHTTPSServerSSEOutlivesShortWriteTimeout proves the reasoning behind
// the 10-minute write timeout doesn't depend on it: an SSE-style writer
// that extends its own per-write deadline (exactly as internal/api's
// writeSSE does, via http.ResponseController.SetWriteDeadline) survives
// a server WriteTimeout far shorter than the stream's total lifetime.
func TestHTTPSServerSSEOutlivesShortWriteTimeout(t *testing.T) {
	const shortTimeout = 50 * time.Millisecond
	const writes = 6
	const writeSpacing = 30 * time.Millisecond // > shortTimeout, so an un-extended deadline would kill the stream

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		for i := 0; i < writes; i++ {
			_ = rc.SetWriteDeadline(time.Now().Add(shortTimeout))
			if _, err := io.WriteString(w, "data: x\n\n"); err != nil {
				t.Errorf("write %d failed before the stream's total lifetime: %v", i, err)
				return
			}
			_ = rc.Flush()
			time.Sleep(writeSpacing)
		}
	}))
	ts.Config.ReadHeaderTimeout = gatewayReadHeaderTimeout
	ts.Config.IdleTimeout = gatewayIdleTimeout
	ts.Config.WriteTimeout = shortTimeout
	ts.StartTLS()
	defer ts.Close()

	client := ts.Client()
	client.Timeout = time.Duration(writes+2) * writeSpacing * 2
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := len(body) / len("data: x\n\n"); got != writes {
		t.Fatalf("received %d SSE frames (body=%q), want %d — the short server WriteTimeout cut the stream short", got, body, writes)
	}
}

// ── The 80 handler ──

func TestHTTPServer_ServesReplicatedHTTP01Token(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(67, 0)}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)

	dir := t.TempDir()
	cache := NewCache(dir, nil, p, nil, nil)
	// Simulate a replicated entry having already been applied, the same
	// way cmd/anvil's gossip hook would call ApplyReceived — see
	// acmecache_test.go for that path in isolation.
	if err := cache.dir.Put(context.Background(), "tok123+http-01", []byte("the-key-authorization")); err != nil {
		t.Fatal(err)
	}

	// HostPolicy gates HTTPHandler's own token serving too
	// (autocert.go:405), so the requested host must be one this
	// gateway's Policy allows — exactly as in the real ACME flow,
	// where the CA only validates a domain this gateway already asked
	// a certificate for.
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache, Policy: p})
	srv := NewHTTPServer(":0", manager, p, "")

	req := httptest.NewRequest("GET", "http://allowed.example.org/.well-known/acme-challenge/tok123", nil)
	rw := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q, want 200", rw.Code, rw.Body.String())
	}
	if rw.Body.String() != "the-key-authorization" {
		t.Fatalf("body = %q, want the replicated token value", rw.Body.String())
	}
}

func TestHTTPServer_RedirectsAllowedHost(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(64, 0)}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache, Policy: p})
	srv := NewHTTPServer(":0", manager, p, "")

	req := httptest.NewRequest("GET", "http://allowed.example.org/some/path?x=1", nil)
	rw := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusPermanentRedirect)
	}
	if loc := rw.Header().Get("Location"); loc != "https://allowed.example.org/some/path?x=1" {
		t.Fatalf("Location = %q, want https://allowed.example.org/some/path?x=1", loc)
	}
}

func TestHTTPServer_RedirectsAPIHost(t *testing.T) {
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache})
	srv := NewHTTPServer(":0", manager, nil, "admin.example.org")

	req := httptest.NewRequest("GET", "http://admin.example.org/status", nil)
	rw := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want %d", rw.Code, http.StatusPermanentRedirect)
	}
	if loc := rw.Header().Get("Location"); loc != "https://admin.example.org/status" {
		t.Fatalf("Location = %q, want https://admin.example.org/status", loc)
	}
}

func TestHTTPServer_404sOthers(t *testing.T) {
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(65, 0)}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache, Policy: p})
	srv := NewHTTPServer(":0", manager, p, "admin.example.org")

	req := httptest.NewRequest("GET", "http://not-a-site.example.org/", nil)
	rw := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rw.Code)
	}
}
