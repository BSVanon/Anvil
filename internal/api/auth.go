package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
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
// semantics. Local reverse proxies are trusted for their rightmost XFF entry
// even when trustProxy is disabled, which preserves per-client buckets for the
// shipped local nginx deployment without trusting direct remote clients.
func clientIP(r *http.Request, trustProxy bool, hops int) string {
	peer := remotePeer(r.RemoteAddr)
	entries := xForwardedForEntries(r.Header.Values("X-Forwarded-For"))
	if len(entries) == 0 {
		return peer
	}

	chosen := ""
	if trustProxy {
		if hops < 1 {
			hops = 1
		}
		idx := len(entries) - hops
		if idx < 0 {
			idx = 0
		}
		chosen = entries[idx]
	} else if ip := net.ParseIP(peer); ip != nil && ip.IsLoopback() {
		chosen = entries[len(entries)-1]
	}
	if chosen == "" {
		return peer
	}
	if ip := parseForwardedIP(chosen); ip != nil {
		return ip.String()
	}
	return peer
}

func remotePeer(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return addr
}

func xForwardedForEntries(values []string) []string {
	var entries []string
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			if entry = strings.TrimSpace(entry); entry != "" {
				entries = append(entries, entry)
			}
		}
	}
	return entries
}

func parseForwardedIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return net.ParseIP(host)
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	}
	return nil
}

func rateLimitKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return net.IP(parsed.To16()[:8]).String() + "/64"
}
