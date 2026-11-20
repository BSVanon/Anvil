package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/clientkey"
)

// requireAuth rejects requests without a valid bearer token.
// Accepts either "Authorization: Bearer <token>" or "X-App-Token: <token>".
// If no auth token is configured, ALL writes are rejected — secure by default.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Handle CORS preflight for authenticated endpoints
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-App-Token, X-Anvil-Auth, Authorization, X402-Proof")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if s.authToken == "" {
			writeError(w, http.StatusForbidden, "no auth token configured — write endpoints disabled")
			return
		}

		// Check X-Anvil-Auth (operator wallet/write auth), then Authorization header.
		// X-App-Token is reserved for app topic gating — not used for operator auth.
		token := r.Header.Get("X-Anvil-Auth")
		if token == "" {
			auth := r.Header.Get("Authorization")
			if len(auth) > 7 && auth[:7] == "Bearer " {
				token = auth[7:]
			}
		}

		if token != s.authToken {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// Add CORS headers to authenticated responses too
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next(w, r)
	}
}

// requireAuthSSE is like requireAuth but also accepts ?token= query parameter.
// SSE endpoints need this because EventSource cannot set custom HTTP headers.
// Scoped only to SSE routes — write endpoints must NOT use this.
func (s *Server) requireAuthSSE(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Anvil-Auth, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if s.authToken == "" {
			writeError(w, http.StatusForbidden, "no auth token configured")
			return
		}

		// Check headers first (same as requireAuth)
		token := r.Header.Get("X-Anvil-Auth")
		if token == "" {
			auth := r.Header.Get("Authorization")
			if len(auth) > 7 && auth[:7] == "Bearer " {
				token = auth[7:]
			}
		}
		// SSE fallback: accept ?token= query param (EventSource can't set headers)
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token != s.authToken {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
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
	trustProxy bool          // if true, honor X-Forwarded-For hop selection
	trustHops  int           // number of trusted proxy hops when trustProxy is true
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
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
	return newRateLimiter(rate, burst, trustProxy, 1)
}

// NewRateLimiterWithBurst creates a rate limiter with an explicit burst size
// and trusted proxy hop count. A non-positive burst defaults to the rate.
func NewRateLimiterWithBurst(rate, burst int, trustProxy bool, trustHops int) *RateLimiter {
	if rate <= 0 {
		rate = 100
	}
	if burst <= 0 {
		burst = rate
	}
	return newRateLimiter(rate, burst, trustProxy, trustHops)
}

func newRateLimiter(rate, burst int, trustProxy bool, trustHops int) *RateLimiter {
	if trustHops < 1 {
		trustHops = 1
	}
	rl := &RateLimiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		burst:      burst,
		cleanup:    5 * time.Minute,
		trustProxy: trustProxy,
		trustHops:  trustHops,
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
		key := rateLimitKey(clientIP(r, rl.trustProxy, rl.trustHops))
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

// clientIP extracts a canonical client IP using the configured proxy trust
// semantics (clientkey.IP, which the overlay route guard shares).
func clientIP(r *http.Request, trustProxy bool, hops int) string {
	return clientkey.IP(r, trustProxy, hops)
}

// rateLimitKey is the bucket key for ip: ip itself, or the /64 of an IPv6
// address (clientkey.Key).
func rateLimitKey(ip string) string { return clientkey.Key(ip) }
