package gateway

import (
	"sync"
	"time"
)

const (
	// floodGuardRate/floodGuardBurst are decision 4's last bullet: the
	// global rate limit on speculative TXT lookups for hosts with no
	// domain entry. Not operator-configurable — B7a's field list
	// (internal/config.GatewayConfig) has no key for it.
	floodGuardRate  = 5
	floodGuardBurst = 20

	// siteTrafficRate/siteTrafficBurst are decision 8's per-client site
	// traffic limiter. Also not operator-configurable in B7a.
	siteTrafficRate  = 50
	siteTrafficBurst = 200

	// limiterSweepBound is how many distinct buckets a limiter tolerates
	// before it sweeps idle ones on the next Allow call. Only the
	// per-client site limiter ever approaches this; the flood guard has
	// exactly one bucket (key "").
	limiterSweepBound = 10000
)

// limiter is a token-bucket rate limiter keyed by an arbitrary string.
// Called with key "" it behaves as a single global bucket (the TXT flood
// guard, decision 4); called with a per-client key (clientkey.Key of
// clientkey.IP) it is a per-client limiter (site traffic, decision 8) —
// same algorithm internal/api's RateLimiter uses, kept here instead of
// imported so this package has no dependency on internal/api.
//
// Stale buckets are swept lazily, on Allow, once the map grows past
// limiterSweepBound, rather than by a background goroutine: a limiter with
// no traffic costs nothing, and nothing needs to Close() one in a test.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func newLimiter(rate, burst int) *limiter {
	return &limiter{
		rate:    float64(rate),
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow reports whether a request keyed by key may proceed, refilling
// key's bucket by elapsed time since it was last seen.
func (l *limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= limiterSweepBound {
			l.evictStale(now)
		}
		l.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictStale drops buckets idle for more than a minute. Called with mu
// held, and only once the map has grown past limiterSweepBound.
func (l *limiter) evictStale(now time.Time) {
	cutoff := now.Add(-time.Minute)
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
