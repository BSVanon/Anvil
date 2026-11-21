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

// TestHostPolicy_RefusesLoopbackHost exercises newHostPolicy's own
// returned function directly, against every shape it defends against —
// including "localhost" and "::1", neither of which actually reaches
// this function via the real autocert.Manager.GetCertificate path at
// all: that entry point refuses any server name with no dot in it
// before HostPolicy ever runs (autocert.go:255-256 at v0.59.0), and
// both of those have none. Exercising newHostPolicy directly for them
// is still correct — defense in depth, right if HostPolicy is ever
// reached some other way, or if that upstream pre-check ever changes —
// while TestNewACMEManager_RefusesLoopbackAndIPLiteralWithoutACMECall
// (below) proves the dotted cases ("127.0.0.1", "127.5.5.5") really do
// reach this refusal through the real, wired-up Manager.
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

// TestHostPolicy_RefusesIPLiteral is RefusesLoopbackHost's counterpart
// for non-loopback IP literals, with the same caveat: "2001:db8::1" has
// no dot and never reaches this function via the real GetCertificate
// path either, for the reason given in RefusesLoopbackHost's doc
// comment. "93.184.216.34" is also covered, through the real Manager,
// by TestNewACMEManager_RefusesLoopbackAndIPLiteralWithoutACMECall
// below.
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

// TestNewACMEManager_RefusesLoopbackAndIPLiteralWithoutACMECall is the
// integration-level test: loopback and IP-literal hosts refused through
// the real autocert.Manager.GetCertificate, with a real
// tls.ClientHelloInfo — not just through newHostPolicy's own returned
// function in isolation, above — the same proof
// TestNewACMEManager_RefusesUnallowedHostWithoutACMECall already gives
// an unknown host, extended to these two refusal reasons.
//
// Only hosts containing a dot are usable here: autocert's own
// GetCertificate refuses anything else — "localhost", "::1",
// "2001:db8::1" — for an unrelated reason, before HostPolicy ever runs
// (see RefusesLoopbackHost's doc comment above), so asserting
// errHostNotAllowed for those specific inputs through this path would
// be testing the wrong thing; they stay covered directly against
// newHostPolicy instead.
func TestNewACMEManager_RefusesLoopbackAndIPLiteralWithoutACMECall(t *testing.T) {
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(64, 0)}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)
	cache := NewCache(t.TempDir(), nil, nil, nil, nil)
	manager := NewACMEManager(ACMEManagerConfig{
		Cache: cache, Policy: p, Directory: ts.URL, AcceptTOS: true,
	})

	for _, host := range []string{"127.0.0.1", "127.5.5.5", "93.184.216.34"} {
		_, err := manager.GetCertificate(&tls.ClientHelloInfo{
			ServerName:   host,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		})
		if err == nil {
			t.Errorf("GetCertificate succeeded for %q, want it refused", host)
		} else if !errors.Is(err, errHostNotAllowed) {
			t.Errorf("host %q: error = %v, want errHostNotAllowed", host, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("the fake ACME directory was hit %d times for loopback/IP-literal hosts, want 0", got)
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

// TestHTTPServer_ServesHTTP01TokenReceivedViaApplyReceived is the
// required end-to-end test: ServesReplicatedHTTP01Token, above, seeds
// its entry with a direct cache.dir.Put, bypassing the one path a
// value like this actually arrives by — a peer's MsgACMEChallenge,
// landing on ApplyReceived (acme_replication.go). This test goes
// through ApplyReceived itself, then confirms the port-80 handler
// serves exactly what it received: the two halves of this feature —
// receiving a replicated entry, and serving one — proved together, not
// each only against a cache seeded by hand.
func TestHTTPServer_ServesHTTP01TokenReceivedViaApplyReceived(t *testing.T) {
	const senderHex = "02331111111111111111111111111111111111111111111111111111111111bb"
	fake := &fakeTXTLookup{records: []string{"ordfs=" + testOutpoint(68, 0)}}
	p, _, _ := newTestPolicy(t, "domain allowed.example.org\n", fake)

	cache := NewCache(t.TempDir(), nil, p, []string{senderHex}, nil)
	if err := cache.ApplyReceived(senderHex, "tok456+http-01", []byte("the-key-authorization"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("ApplyReceived: %v", err)
	}

	// Same HostPolicy-gates-HTTPHandler-too note as
	// ServesReplicatedHTTP01Token above.
	manager := NewACMEManager(ACMEManagerConfig{Cache: cache, Policy: p})
	srv := NewHTTPServer(":0", manager, p, "")

	req := httptest.NewRequest("GET", "http://allowed.example.org/.well-known/acme-challenge/tok456", nil)
	rw := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q, want 200", rw.Code, rw.Body.String())
	}
	if rw.Body.String() != "the-key-authorization" {
		t.Fatalf("body = %q, want the value ApplyReceived stored", rw.Body.String())
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
