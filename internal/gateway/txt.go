package gateway

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const txtLookupTimeout = 3 * time.Second

// txtLookuper is the subset of *net.Resolver that Resolver needs — narrow
// so tests can fake DNS answers and errors (including a NXDOMAIN-shaped
// *net.DNSError) without a real network.
type txtLookuper interface {
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// parseOrdfsTXT applies the parsing rules to the TXT records
// already fetched for _ordfs.<host>. Go's resolver already concatenates
// each record's character-strings into one entry of records, so that part
// needs no code here. The rest: the key is case-insensitive
// and space-trimmed, the value must be "ordfs=<64 hex>_<decimal vout>",
// duplicate records with the same value are fine, and zero or
// more-than-one DISTINCT valid value means no mapping.
func parseOrdfsTXT(records []string) (origin string, ok bool) {
	found := map[string]struct{}{}
	for _, rec := range records {
		key, value, hasEq := strings.Cut(strings.TrimSpace(rec), "=")
		if !hasEq {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(key), "ordfs") {
			continue
		}
		outpoint, ok := parseOutpoint(strings.TrimSpace(value))
		if !ok {
			continue
		}
		found[outpoint] = struct{}{}
	}
	if len(found) != 1 {
		return "", false
	}
	for o := range found {
		return o, true
	}
	return "", false // unreachable
}

// isNoSuchRecord reports whether err is DNS's definitive "no such record"
// answer (NXDOMAIN/NODATA), as opposed to a genuine resolver failure
// (timeout, SERVFAIL, network error) — the distinction the caller
// stale-grace fallback depends on: a legitimate "no mapping" answer is
// authoritative and must not be masked by a stale, previously-good one.
func isNoSuchRecord(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

type txtCacheEntry struct {
	origin   string
	ok       bool
	expires  time.Time
	accessed time.Time
}

type lastGoodEntry struct {
	origin string
	at     time.Time
}

// ResolverConfig configures NewResolver. Zero values use the default
// defaults.
type ResolverConfig struct {
	PositiveTTL time.Duration // default 5m
	NegativeTTL time.Duration // default 1m — also the resolver-error retry interval; see Lookup
	StaleGrace  time.Duration // default 24h
	Stats       *Counters     // default a fresh, unshared Counters
}

// Resolver performs cached, singleflighted TXT lookup:
// flood-guarded _ordfs.<host> resolver. Construct with NewResolver.
type Resolver struct {
	lookup      txtLookuper
	positiveTTL time.Duration
	negativeTTL time.Duration
	staleGrace  time.Duration
	now         func() time.Time
	stats       *Counters

	mu    sync.Mutex
	cache map[string]*txtCacheEntry

	lastGoodMu sync.Mutex
	lastGood   map[string]lastGoodEntry

	sf    singleflight.Group
	flood *limiter
}

// NewResolver builds a Resolver using the system DNS resolver.
func NewResolver(cfg ResolverConfig) *Resolver {
	if cfg.PositiveTTL <= 0 {
		cfg.PositiveTTL = 5 * time.Minute
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = time.Minute
	}
	if cfg.StaleGrace <= 0 {
		cfg.StaleGrace = 24 * time.Hour
	}
	if cfg.Stats == nil {
		cfg.Stats = &Counters{}
	}
	return &Resolver{
		lookup:      net.DefaultResolver,
		positiveTTL: cfg.PositiveTTL,
		negativeTTL: cfg.NegativeTTL,
		staleGrace:  cfg.StaleGrace,
		now:         time.Now,
		stats:       cfg.Stats,
		cache:       make(map[string]*txtCacheEntry),
		lastGood:    make(map[string]lastGoodEntry),
		flood:       newLimiter(floodGuardRate, floodGuardBurst),
	}
}

// Lookup resolves host's _ordfs TXT to an origin, through the cache
// a fresh cache entry answers immediately — regardless of
// speculative, since a cache hit makes no new resolver call at all and so
// can never be what the flood guard exists to limit — a miss or
// expiry triggers one singleflighted DNS lookup per host, bounded by a 3s
// timeout independent of ctx (singleflight shares this call across every
// concurrent caller for host, so it must not depend on any one of their
// contexts' cancellation). A genuine resolver error — not a definitive
// "no such record" answer — falls back to the last known-good origin for
// up to StaleGrace; past that, or with no prior good answer, it's treated
// as no mapping, same as a definitive negative DNS answer.
//
// speculative marks a lookup for a Host with no explicit "domain" entry
// (it can only possibly match through an "origin" entry) — Policy passes
// !hasDomain. Only a speculative lookup that MISSES the cache consults
// the global flood guard, so a flood of random
// Host headers can't run the resolver ragged just because some "origin"
// entries exist to speculatively match against, while a cached, legitimate
// answer is never throttled no matter how busy the guard's global bucket
// is; the guard runs after the cache lookup.
func (r *Resolver) Lookup(ctx context.Context, host string, speculative bool) (origin string, ok bool) {
	if ctx.Err() != nil {
		return "", false
	}

	now := r.now()
	if e := r.cacheGet(host, now); e != nil {
		return e.origin, e.ok
	}

	if speculative && !r.flood.Allow("") {
		return "", false
	}

	r.stats.TXTLookups.Add(1)
	v, err, _ := r.sf.Do(host, func() (interface{}, error) {
		lookupCtx, cancel := context.WithTimeout(context.Background(), txtLookupTimeout)
		defer cancel()
		return r.lookup.LookupTXT(lookupCtx, "_ordfs."+host)
	})

	now = r.now() // the lookup may have taken a while
	if err != nil {
		if isNoSuchRecord(err) {
			r.cacheSet(host, "", false, r.negativeTTL, now)
			return "", false
		}
		if lg, ok := r.lastGoodFor(host); ok && now.Sub(lg.at) < r.staleGrace {
			r.stats.TXTStale.Add(1)
			// Cached briefly (the negative TTL doubles as the resolver-
			// error retry interval) so an outage doesn't force a fresh
			// DNS attempt on every single request.
			r.cacheSet(host, lg.origin, true, r.negativeTTL, now)
			return lg.origin, true
		}
		r.cacheSet(host, "", false, r.negativeTTL, now)
		return "", false
	}

	records, _ := v.([]string)
	origin, ok = parseOrdfsTXT(records)
	if ok {
		r.cacheSet(host, origin, true, r.positiveTTL, now)
		r.setLastGood(host, origin, now)
		return origin, true
	}
	r.cacheSet(host, "", false, r.negativeTTL, now)
	return "", false
}

func (r *Resolver) cacheGet(host string, now time.Time) *txtCacheEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[host]
	if !ok || now.After(e.expires) {
		return nil
	}
	e.accessed = now
	return e
}

func (r *Resolver) cacheSet(host, origin string, ok bool, ttl time.Duration, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[host] = &txtCacheEntry{origin: origin, ok: ok, expires: now.Add(ttl), accessed: now}
	if len(r.cache) > txtCacheBound {
		r.evictOldest()
	}
}

// txtCacheBound is the LRU bound of 10,000 hosts.
const txtCacheBound = 10000

// evictOldest removes the least-recently-accessed cache entry. Called
// with mu held. O(n) over the bound — mirrors internal/content's cache,
// which uses the same oldest-wins scan at the same bound — and eviction
// is rare (only once the bound is exceeded), so the scan cost is a
// non-issue here.
func (r *Resolver) evictOldest() {
	var oldestHost string
	var oldestAt time.Time
	first := true
	for h, e := range r.cache {
		if first || e.accessed.Before(oldestAt) {
			oldestHost, oldestAt, first = h, e.accessed, false
		}
	}
	if oldestHost != "" {
		delete(r.cache, oldestHost)
	}
}

func (r *Resolver) lastGoodFor(host string) (lastGoodEntry, bool) {
	r.lastGoodMu.Lock()
	defer r.lastGoodMu.Unlock()
	e, ok := r.lastGood[host]
	return e, ok
}

func (r *Resolver) setLastGood(host, origin string, at time.Time) {
	r.lastGoodMu.Lock()
	defer r.lastGoodMu.Unlock()
	r.lastGood[host] = lastGoodEntry{origin: origin, at: at}
	if len(r.lastGood) > txtCacheBound {
		var oldestHost string
		var oldestAt time.Time
		first := true
		for h, e := range r.lastGood {
			if first || e.at.Before(oldestAt) {
				oldestHost, oldestAt, first = h, e.at, false
			}
		}
		if oldestHost != "" {
			delete(r.lastGood, oldestHost)
		}
	}
}
