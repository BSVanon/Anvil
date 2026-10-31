package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterAllowsBurst(t *testing.T) {
	rl := NewRateLimiter(10, false) // 10 req/s

	// Should allow up to burst (10) requests immediately
	for i := 0; i < 10; i++ {
		if !rl.Allow("testip") {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}

	// Next request should be denied (bucket empty)
	if rl.Allow("testip") {
		t.Fatal("request beyond burst should be denied")
	}
}

func TestRateLimiterDifferentKeys(t *testing.T) {
	rl := NewRateLimiter(5, false)

	// Exhaust key A
	for i := 0; i < 10; i++ {
		rl.Allow("keyA")
	}

	// Key B should still be allowed
	if !rl.Allow("keyB") {
		t.Fatal("different key should have its own bucket")
	}
}

func TestRateLimiterMiddleware429(t *testing.T) {
	rl := NewRateLimiter(2, false) // very low for testing

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust the bucket
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		w := httptest.NewRecorder()
		handler(w, req)
	}

	// Next request should be 429
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestRateLimiterMiddlewareXForwardedFor(t *testing.T) {
	rl := NewRateLimiter(2, true) // trust_proxy = true for XFF test

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Exhaust IP A via X-Forwarded-For
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
		w := httptest.NewRecorder()
		handler(w, req)
	}

	// IP B should still work
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("different IP should be allowed, got %d", w.Code)
	}
}

func TestClientIPParsing(t *testing.T) {
	tests := []struct {
		remoteAddr string
		xff        []string
		trustProxy bool
		hops       int
		expected   string
	}{
		{"127.0.0.1:5555", []string{"forged, 203.0.113.7"}, false, 1, "203.0.113.7"},
		{"[::1]:5555", []string{"198.51.100.1, 203.0.113.7"}, false, 1, "203.0.113.7"},
		{"198.51.100.2:1234", []string{"1.2.3.4"}, false, 1, "198.51.100.2"},
		{"198.51.100.2:1234", []string{"198.51.100.1, 198.51.100.2"}, true, 1, "198.51.100.2"},
		{"198.51.100.2:1234", []string{"198.51.100.1, 198.51.100.2, 198.51.100.3"}, true, 2, "198.51.100.2"},
		{"198.51.100.2:1234", []string{"198.51.100.1, 198.51.100.2"}, true, 9, "198.51.100.1"},
		{"198.51.100.2:1234", []string{"garbage"}, true, 1, "198.51.100.2"},
		{"198.51.100.2:1234", []string{"198.51.100.1", "198.51.100.2, 198.51.100.3"}, true, 2, "198.51.100.2"},
		{"198.51.100.2", nil, false, 1, "198.51.100.2"},
		{"2001:db8::1", nil, false, 1, "2001:db8::1"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remoteAddr
		for _, xff := range tt.xff {
			r.Header.Add("X-Forwarded-For", xff)
		}
		got := clientIP(r, tt.trustProxy, tt.hops)
		if got != tt.expected {
			t.Errorf("clientIP(%q, xff=%q) = %q, want %q", tt.remoteAddr, tt.xff, got, tt.expected)
		}
	}
}

func TestRateLimiterIPv6PrefixKey(t *testing.T) {
	rl := NewRateLimiterWithBurst(1, 1, false, 1)
	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	request := func(addr string) int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		handler(w, req)
		return w.Code
	}
	if got := request("[2001:db8:1:2::1]:1234"); got != http.StatusOK {
		t.Fatalf("first IPv6 request: got %d", got)
	}
	if got := request("[2001:db8:1:2::2]:1234"); got != http.StatusTooManyRequests {
		t.Fatalf("same /64 should share a bucket, got %d", got)
	}
	if got := request("[2001:db8:1:3::1]:1234"); got != http.StatusOK {
		t.Fatalf("different /64 should have another bucket, got %d", got)
	}
}

func TestMessageboxAndReadLimitersAreSeparate(t *testing.T) {
	newServer := func() *Server {
		srv := testServer(t)
		srv.rateLimiter = NewRateLimiterWithBurst(1, 1, false, 1)
		srv.messageboxLimiter = NewRateLimiterWithBurst(1, 1, false, 1)
		srv.mux = http.NewServeMux()
		srv.routes()
		return srv
	}
	request := func(srv *Server, method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "203.0.113.7:1234"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	srv := newServer()
	request(srv, http.MethodPost, "/sendMessage")
	if got := request(srv, http.MethodPost, "/sendMessage").Code; got != http.StatusTooManyRequests {
		t.Fatalf("exhausted messagebox limiter: got %d, want 429", got)
	}
	if got := request(srv, http.MethodGet, "/status").Code; got != http.StatusOK {
		t.Fatalf("messagebox limit must not affect read limiter: got %d", got)
	}

	srv = newServer()
	request(srv, http.MethodGet, "/status")
	if got := request(srv, http.MethodGet, "/status").Code; got != http.StatusTooManyRequests {
		t.Fatalf("exhausted read limiter: got %d, want 429", got)
	}
	if got := request(srv, http.MethodPost, "/sendMessage").Code; got == http.StatusTooManyRequests {
		t.Fatal("read limit must not affect messagebox limiter")
	}
}

func TestMessageboxLimiterActiveWithoutGeneralRateLimit(t *testing.T) {
	srv := testServer(t)
	if srv.rateLimiter != nil {
		t.Fatal("test server should not have a general rate limiter")
	}
	srv.messageboxLimiter = NewRateLimiterWithBurst(1, 1, false, 1)
	srv.mux = http.NewServeMux()
	srv.routes()

	request := func() int {
		req := httptest.NewRequest(http.MethodPost, "/sendMessage", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w.Code
	}
	request()
	if got := request(); got != http.StatusTooManyRequests {
		t.Fatalf("messagebox route should be limited without a general limiter, got %d", got)
	}
}

func TestMessageboxBRC31RateLimitResponse(t *testing.T) {
	srv := testServer(t)
	_, _, srv.nodeWallet = newKeyWallet(t)
	srv.messageboxLimiter = NewRateLimiterWithBurst(1, 1, false, 1)
	srv.mux = http.NewServeMux()
	srv.routes()

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/auth", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	request()
	w := request()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("handshake should be rate limited, got %d", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("BRC-31 429 missing CORS header: %q", got)
	}
	body, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), messageboxRateLimitBody; got != want {
		t.Fatalf("429 body = %s, want %s", got, want)
	}
}

func TestMessageboxBRC31SSERateLimitResponseHasCORS(t *testing.T) {
	srv := testServer(t)
	_, _, srv.nodeWallet = newKeyWallet(t)
	srv.messageboxLimiter = NewRateLimiterWithBurst(1, 1, false, 1)
	srv.mux = http.NewServeMux()
	srv.routes()

	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/messages/subscribe?messageBox=box&token=invalid", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	request()
	w := request()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("SSE status = %d, want 429", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("SSE 429 missing CORS header: %q", got)
	}
}

func TestOpenReadEndpointsAreRateLimited(t *testing.T) {
	srv := testServer(t)
	// Default test server has no rate limiter — open reads should work fine
	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestServerWithRateLimit(t *testing.T) {
	// Create a server with a very low rate limit
	srv := testServer(t)
	// Manually set a rate limiter on the server (test-only, after construction)
	srv.rateLimiter = NewRateLimiter(1, false)
	// Re-initialize routes with the rate limiter
	srv.mux = http.NewServeMux()
	srv.routes()

	// First request should succeed
	req := httptest.NewRequest("GET", "/status", nil)
	req.RemoteAddr = "5.5.5.5:9999"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w.Code)
	}

	// Exhaust the bucket
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/status", nil)
		req.RemoteAddr = "5.5.5.5:9999"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
	}

	// Should be rate limited now
	req2 := httptest.NewRequest("GET", "/status", nil)
	req2.RemoteAddr = "5.5.5.5:9999"
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after exhausting rate limit, got %d", w2.Code)
	}

	// Authenticated writes should NOT be rate limited
	req3 := httptest.NewRequest("POST", "/broadcast", nil)
	req3.RemoteAddr = "5.5.5.5:9999"
	req3.Header.Set("Authorization", "Bearer test-token")
	w3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w3, req3)
	// Should not be 429 — should be 400 (empty body) instead
	if w3.Code == http.StatusTooManyRequests {
		t.Fatal("write endpoints should not be rate limited")
	}
}

func TestGeneralLimiterHonorsTrustProxyHops(t *testing.T) {
	s := NewServer(ServerConfig{RateLimit: 5, TrustProxy: true, TrustProxyHops: 2})
	if s.rateLimiter == nil {
		t.Fatal("general limiter not built")
	}
	if s.rateLimiter.trustHops != 2 || s.messageboxLimiter.trustHops != 2 {
		t.Fatalf("trustHops general=%d messagebox=%d, want 2", s.rateLimiter.trustHops, s.messageboxLimiter.trustHops)
	}
	if s.rateLimiter.burst != 10 {
		t.Fatalf("general burst = %d, want 10 (rate 5, min 10)", s.rateLimiter.burst)
	}
}
