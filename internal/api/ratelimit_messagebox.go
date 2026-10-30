package api

import "net/http"

const messageboxRateLimitBody = `{"status":"error","code":"ERR_RATE_LIMITED","description":"Too many requests. Please retry later.","error":"Too many requests. Please retry later."}`

// messageboxRateLimit applies the messagebox-specific limiter before message
// authentication, including the BRC-31 handshake endpoint.
func messageboxRateLimit(rl *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		key := rateLimitKey(clientIP(r, rl.trustProxy, rl.trustHops))
		if !rl.Allow(key) {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(messageboxRateLimitBody))
			return
		}
		next.ServeHTTP(w, r)
	})
}
