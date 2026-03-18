package api

import (
	"net/http"
	"sync"
	"time"
)

// requireAuth rejects requests without a valid bearer token.
// If no auth token is configured, ALL writes are rejected — secure by default.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" {
			writeError(w, http.StatusForbidden, "no auth token configured — write endpoints disabled")
			return
		}
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.authToken
		if auth != expected {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// RateLimiter implements a token-bucket rate limiter keyed by client IP.
// Zero-value is not usable — use NewRateLimiter.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	rate       int           // tokens per second
	burst      int           // max tokens (burst capacity)
	cleanup    time.Duration // how often to evict stale entries
	trustProxy bool          // if true, use X-Forwarded-For; if false, use RemoteAddr only
}

type bucket struct {
	tokens    float64
	lastSeen  time.Time
}

// NewRateLimiter creates a rate limiter. rate is requests/second, burst
// is the maximum burst size (defaults to rate if zero). If trustProxy
// is true, X-Forwarded-For is used for client IP; otherwise RemoteAddr only.
func NewRateLimiter(rate int, trustProxy bool) *RateLimiter {
	if rate <= 0 {
		rate = 100
	}
	burst := rate
	if burst < 10 {
		burst = 10
	}
	rl := &RateLimiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		burst:      burst,
		cleanup:    5 * time.Minute,
		trustProxy: trustProxy,
	}
	go rl.evictLoop()
	return rl
}

// Allow checks whether a request from the given key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: float64(rl.burst) - 1, lastSeen: now}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * float64(rl.rate)
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Middleware returns an http.HandlerFunc wrapper that rate-limits by client IP.
func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r, rl.trustProxy)
		if !rl.Allow(key) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}

// evictLoop periodically removes stale entries to prevent unbounded memory growth.
func (rl *RateLimiter) evictLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.cleanup)
		for k, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the client IP. When trustProxy is true, X-Forwarded-For
// is used (first IP only). When false, X-Forwarded-For is ignored entirely
// to prevent spoofing on directly-exposed nodes.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
			return xff
		}
	}
	// Fall back to RemoteAddr (strip port)
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
