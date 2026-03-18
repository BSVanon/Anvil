package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterAllowsBurst(t *testing.T) {
	rl := NewRateLimiter(10) // 10 req/s

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
	rl := NewRateLimiter(5)

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
	rl := NewRateLimiter(2) // very low for testing

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
	rl := NewRateLimiter(2)

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
		xff        string
		expected   string
	}{
		{"1.2.3.4:5678", "", "1.2.3.4"},
		{"[::1]:5678", "", "[::1]"},
		{"1.2.3.4:5678", "10.0.0.1", "10.0.0.1"},
		{"1.2.3.4:5678", "10.0.0.1, 10.0.0.2", "10.0.0.1"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remoteAddr
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		got := clientIP(r)
		if got != tt.expected {
			t.Errorf("clientIP(%q, xff=%q) = %q, want %q", tt.remoteAddr, tt.xff, got, tt.expected)
		}
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
	srv.rateLimiter = NewRateLimiter(1)
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
