package gateway

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Scan bounds.
const (
	scopeMaxDepth     = 4
	scopeMaxOutpoints = 2000
	scopeMaxBytes     = 32 << 20 // 32 MiB
)

// scanScope's loop checks bytesFetched against scopeMaxBytes before
// each fetch, not against the next fetch's size — content.Inscription has
// no up-front, pre-fetch size signal to check against (its only per-fetch
// bound is internal/content/woc_limit.go's maxWoCTxHexBytes, 32 MiB of hex
// decoding to a 16 MiB transaction, applied inside the fetch itself, not
// exposed to callers beforehand) — so the scan can run up to one more
// fetch past scopeMaxBytes before the next loop check stops it: a 16 MiB
// single fetch is this scan's worst-case overshoot, making ~48 MiB
// (scopeMaxBytes plus one maximum fetch) the worst-case transient memory
// one scan's fetches hold, on top of content.Server's own, separate
// inscription cache.

// scopeScanTimeout bounds the shared, singleflighted scan's own detached
// context. The scan runs independently of whichever caller happened
// to trigger it (see InScope), so this is now the only deadline it has,
// and it has to absorb a run of individually-slow-but-legitimate fetches
// without tripping, or every such scan would go uncached and re-run on
// every request. A single Inscription() fetch can itself legitimately
// take up to ~30s in the worst case — WhatsOnChain's hex endpoint and its
// JSON fallback can each take the content server's own 15s HTTP timeout
// (internal/content/serve.go's client field) before falling through — so
// 30s is this scan's per-fetch floor, not a sane scan-wide ceiling. Two
// minutes gives room for several such slow-but-legitimate fetches in a
// row while staying nowhere near the pathological worst case (up to
// scopeMaxOutpoints sequential fetches against a consistently slow
// source would take hours, far past any caller still waiting on it), so
// a genuinely wedged or consistently slow source still can't hold the
// scan — and the singleflight group every other caller for the same key
// is waiting on — open indefinitely.
const scopeScanTimeout = 2 * time.Minute

// scopeIncompleteCacheTTL and scopeFailedFetchTTL bound retry behavior for
// amplification bound. Before this, an incomplete result was
// never cached at all, so a site that references one persistently
// failing outpoint paid for a full breadth-first rescan — up to
// scopeScanTimeout and scopeMaxOutpoints fetches — on every single
// request; if the failure was a transient upstream 429, every one of
// those repeat scans' fetches fed back into the very rate limit causing
// it. Now: an incomplete result (a fetch error or the scan timing out) is
// cached too, just for this much shorter window, bounding the cost to at
// most one rescan per window rather than one per request. The specific
// outpoint that failed is also, separately, negatively cached for the
// same window, so a second site that happens to reference the very same
// broken outpoint doesn't pay for its own independent retry of it (see
// negativeCachingFetcher). Both default to the same value but are named
// separately since nothing requires them to always match.
const (
	scopeIncompleteCacheTTL = 60 * time.Second
	scopeFailedFetchTTL     = 60 * time.Second
)

// contentFetcher is the subset of *content.Server the scope scanner and
// SiteHandler need — narrow so tests can fake content without a real
// content.Server (which needs a live fetch source).
type contentFetcher interface {
	Inscription(ctx context.Context, txid string, vout int) (data []byte, contentType string, err error)
}

// errOutpointRecentlyFailed is returned in place of a real fetch error
// when negativeCachingFetcher short-circuits a known-recently-failing
// outpoint. scanScope treats it exactly like any other fetch error — the
// node stays in scope (it WAS referenced) but isn't expanded further, and
// the result is marked incomplete — so nothing else needs to know this
// cache exists.
var errOutpointRecentlyFailed = errors.New("outpoint fetch failed recently; still within its negative-cache window")

// negativeCachingFetcher wraps a contentFetcher with the per-outpoint
// half of the amplification bound: a fetch that failed within
// the last scopeFailedFetchTTL is not retried at all — it's reported as
// still failing without ever reaching inner — because a persistently
// failing reference's fetch failures otherwise compound across every
// scan that reaches it, including one for a completely different site's
// origin that happens to reference the same outpoint. The failed map is
// shared across every scan scopeCache runs (constructed once, in
// newScopeCache), not scoped to one (origin, latestOutpoint) key — two
// different sites referencing the same broken outpoint share one
// suppressed fetch, not two independent ones.
type negativeCachingFetcher struct {
	inner contentFetcher
	now   func() time.Time

	mu     sync.Mutex
	failed map[string]time.Time // outpoint -> when its negative cache expires
}

func (f *negativeCachingFetcher) Inscription(ctx context.Context, txid string, vout int) ([]byte, string, error) {
	outpoint := txid + "_" + strconv.Itoa(vout)
	now := f.now()

	f.mu.Lock()
	expires, failing := f.failed[outpoint]
	f.mu.Unlock()
	if failing && now.Before(expires) {
		return nil, "", errOutpointRecentlyFailed
	}

	data, contentType, err := f.inner.Inscription(ctx, txid, vout)
	if err != nil {
		f.mu.Lock()
		f.failed[outpoint] = now.Add(scopeFailedFetchTTL)
		f.mu.Unlock()
		return nil, "", err
	}
	return data, contentType, nil
}

// scopeRefRe matches a literal "/content/<64 hex>_<digits>" reference
// inside a text inscription — the reachability rule. This is
// intentionally just a substring scan of raw bytes, the same way a
// browser or static site finds its own asset URLs; it does not parse
// HTML/CSS/JS/SVG/JSON, so it also catches a reference sitting inside a
// template string, a CSS url(), an SVG attribute or JSON — anywhere the
// literal text appears.
var scopeRefRe = regexp.MustCompile(`/content/([0-9a-fA-F]{64})_([0-9]+)`)

// scopeResult is one scan's reachable outpoint set. complete controls
// caching: true for a scan that ran to its natural end — exhausting
// its queue, or stopping at the deterministic scopeMaxOutpoints/
// scopeMaxBytes/scopeMaxDepth bounds, all of which are complete, correct
// answers by design — false for one cut short by its context (a timeout)
// or by a fetch error (the detached context means no caller's own
// cancellation can reach it any more, so those are the only two ways left
// to end up incomplete). expires is zero for a
// complete result (cached with no TTL, exactly as before); set to
// scopeIncompleteCacheTTL past when it was cached for an incomplete one,
// so a persistently failing reference is bounded to one rescan per
// window rather than one per request, while still eventually trying
// again rather than wedging a site's scope incomplete forever.
type scopeResult struct {
	set      map[string]struct{}
	complete bool
	expires  time.Time
}

func (r *scopeResult) has(outpoint string) bool {
	_, ok := r.set[outpoint]
	return ok
}

// scopeCache caches the result per (origin, latest
// outpoint)" plus "one scan per site at a time", combined: singleflight
// already gives both — concurrent callers for the same key share one
// scan, and its result is memoized under that key. content wraps
// whatever was passed to newScopeCache in a negativeCachingFetcher (fix
// shared scan), so every scan sharing this scopeCache also shares one
// per-outpoint negative-fetch cache. now is overridable in tests, the
// same way Resolver's is.
type scopeCache struct {
	content contentFetcher
	sf      singleflight.Group
	now     func() time.Time
	// history, when set, lists an origin's versions; see versionRoots.
	history func(origin string) []string

	mu    sync.Mutex
	byKey map[string]*scopeResult
	keyOf map[string]string // origin -> its one cached key
}

func newScopeCache(content contentFetcher) *scopeCache {
	sc := &scopeCache{byKey: make(map[string]*scopeResult), keyOf: make(map[string]string), now: time.Now}
	sc.content = &negativeCachingFetcher{
		inner:  content,
		now:    func() time.Time { return sc.now() },
		failed: make(map[string]time.Time),
	}
	return sc
}

// InScope reports whether target (a txid_vout outpoint) is in origin's
// content scope, scanning and caching by (origin, latestOutpoint) if
// needed. origin and latestOutpoint are always themselves in
// scope: they are the scan's roots, not something reachability needs to
// prove.
//
// The shared, singleflighted scan runs under its own context, detached from
// whichever caller happens to trigger it (context.WithoutCancel) and
// bounded by its own timeout (scopeScanTimeout) rather than ctx's
// cancellation — so a caller disconnecting mid-scan can neither truncate
// the scan nor, by extension, ever poison the cache with a truncated
// result for every other caller sharing the same (origin, latestOutpoint)
// key. Every scopeResult (complete or not) is stored in byKey; cacheGet
// is what makes an incomplete one's residency temporary.
func (c *scopeCache) InScope(ctx context.Context, origin, latestOutpoint, target string) bool {
	if target == origin || target == latestOutpoint {
		return true
	}
	key := origin + "|" + latestOutpoint

	if cached := c.cacheGet(key); cached != nil {
		return cached.has(target)
	}

	v, _, _ := c.sf.Do(key, func() (interface{}, error) {
		if cached := c.cacheGet(key); cached != nil {
			return cached, nil
		}

		scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), scopeScanTimeout)
		defer cancel()
		versions, rooted := c.versionRoots(origin, latestOutpoint)
		result := scanScope(scanCtx, c.content, origin, latestOutpoint, versions...)
		if !result.complete || !rooted {
			result.expires = c.now().Add(scopeIncompleteCacheTTL)
		}

		// One result per origin: a new latest version replaces the last.
		c.mu.Lock()
		if prev, ok := c.keyOf[origin]; ok && prev != key {
			delete(c.byKey, prev)
		}
		c.keyOf[origin] = key
		c.byKey[key] = result
		c.mu.Unlock()
		return result, nil
	})
	result, _ := v.(*scopeResult)
	if result == nil {
		return false
	}
	return result.has(target)
}

// cacheGet returns key's cached result if present and not expired. A
// complete result's expires is the zero Time, which is never "after" c's
// current time, so it never expires;
// an incomplete result's non-zero expires does, once c.now() passes it —
// cacheGet then returns nil, same as a plain cache miss, letting InScope
// rescan.
func (c *scopeCache) cacheGet(key string) *scopeResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.byKey[key]
	if !ok {
		return nil
	}
	if !cached.expires.IsZero() && c.now().After(cached.expires) {
		return nil
	}
	return cached
}

type frontierNode struct {
	outpoint string
	depth    int
}

// scanScope performs a breadth-first reachability scan from
// origin and latestOutpoint, bounded by depth, outpoint count and bytes
// fetched. Hitting any of those deterministic bounds simply stops
// expansion — everything found up to that point is a complete, correct
// (if conservative) scope, fit to cache. Stopping because ctx is
// done (the scan's own bounded timeout — see InScope) is different:
// expansion is abandoned early, so the queue may still have held
// references this run never got to discover — the returned set is still
// the best answer available for the caller waiting on it right now, but
// it is marked incomplete, and InScope never caches an incomplete result.
// A per-node fetch error also marks the result incomplete (for the same
// caching reason) but does NOT stop the scan early: that node stays in
// scope (it WAS referenced), it just can't be scanned further for its own
// references, exactly as before — only the final caching decision changes.
//
// versions are further roots: the origin's other versions, newest first.
func scanScope(ctx context.Context, content contentFetcher, origin, latestOutpoint string, versions ...string) *scopeResult {
	visited := map[string]struct{}{}
	// Queue each root once: an untracked origin has latestOutpoint ==
	// origin, and queuing the same outpoint twice would fetch and count it
	// twice against the byte budget for no benefit.
	var queue []frontierNode
	for _, root := range append([]string{origin, latestOutpoint}, versions...) {
		if _, seen := visited[root]; !seen {
			visited[root] = struct{}{}
			queue = append(queue, frontierNode{root, 0})
		}
	}
	bytesFetched := 0
	complete := true

	for len(queue) > 0 && len(visited) < scopeMaxOutpoints && bytesFetched < scopeMaxBytes {
		if err := ctx.Err(); err != nil {
			complete = false
			break
		}
		node := queue[0]
		queue = queue[1:]
		if node.depth >= scopeMaxDepth {
			continue
		}
		txid, vout, ok := splitOutpoint(node.outpoint)
		if !ok {
			continue
		}
		data, contentType, err := content.Inscription(ctx, txid, vout)
		if err != nil {
			complete = false
			continue
		}
		bytesFetched += len(data)
		if !isScannableText(contentType) {
			continue
		}
		for _, m := range scopeRefRe.FindAllStringSubmatch(string(data), -1) {
			ref, ok := parseOutpoint(m[1] + "_" + m[2])
			if !ok {
				continue
			}
			if _, seen := visited[ref]; seen {
				continue
			}
			if len(visited) >= scopeMaxOutpoints {
				break
			}
			visited[ref] = struct{}{}
			queue = append(queue, frontierNode{ref, node.depth + 1})
		}
	}
	return &scopeResult{set: visited, complete: complete}
}

// splitOutpoint splits a normalised "txid_vout" string into its parts.
func splitOutpoint(outpoint string) (txid string, vout int, ok bool) {
	txid, voutStr, hasSep := strings.Cut(outpoint, "_")
	if !hasSep {
		return "", 0, false
	}
	n, err := strconv.Atoi(voutStr)
	if err != nil || n < 0 {
		return "", 0, false
	}
	return txid, n, true
}

// isScannableText reports whether contentType is one of the
// scannable text kinds: HTML, CSS, JS, SVG or JSON.
func isScannableText(contentType string) bool {
	ct := strings.ToLower(contentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	switch strings.TrimSpace(ct) {
	case "text/html", "text/css", "text/javascript", "application/javascript",
		"application/json", "text/json", "image/svg+xml":
		return true
	default:
		return false
	}
}
