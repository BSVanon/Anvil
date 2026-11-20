package gateway

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Decision 6's scan bounds.
const (
	scopeMaxDepth     = 4
	scopeMaxOutpoints = 2000
	scopeMaxBytes     = 32 << 20 // 32 MiB
)

// R3: scanScope's loop checks bytesFetched against scopeMaxBytes before
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
// context (R4). The scan runs independently of whichever caller happened
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

// contentFetcher is the subset of *content.Server the scope scanner and
// SiteHandler need — narrow so tests can fake content without a real
// content.Server (which needs a live fetch source).
type contentFetcher interface {
	Inscription(ctx context.Context, txid string, vout int) (data []byte, contentType string, err error)
}

// scopeRefRe matches a literal "/content/<64 hex>_<digits>" reference
// inside a text inscription — decision 6's reachability rule. This is
// intentionally just a substring scan of raw bytes, the same way a
// browser or static site finds its own asset URLs; it does not parse
// HTML/CSS/JS/SVG/JSON, so it also catches a reference sitting inside a
// template string, a CSS url(), an SVG attribute or JSON — anywhere the
// literal text appears.
var scopeRefRe = regexp.MustCompile(`/content/([0-9a-fA-F]{64})_([0-9]+)`)

// scopeResult is one scan's reachable outpoint set. complete is R4's
// caching gate: true for a scan that ran to its natural end — exhausting
// its queue, or stopping at the deterministic scopeMaxOutpoints/
// scopeMaxBytes/scopeMaxDepth bounds, all of which are complete, correct
// answers by design — false for one cut short by its context (a timeout,
// or a cancellation — though R4's detached context means no caller's own
// cancellation can reach it any more) or by a fetch error. Only a complete
// result may ever be cached (see InScope); an incomplete one is still
// returned to its own caller (the best answer available right now), just
// never memoized for anyone else.
type scopeResult struct {
	set      map[string]struct{}
	complete bool
}

func (r *scopeResult) has(outpoint string) bool {
	_, ok := r.set[outpoint]
	return ok
}

// scopeCache is decision 6's "cache the result per (origin, latest
// outpoint)" plus "one scan per site at a time", combined: singleflight
// already gives both — concurrent callers for the same key share one
// scan, and its result is memoized under that key.
type scopeCache struct {
	content contentFetcher
	sf      singleflight.Group

	mu    sync.Mutex
	byKey map[string]*scopeResult
}

func newScopeCache(content contentFetcher) *scopeCache {
	return &scopeCache{content: content, byKey: make(map[string]*scopeResult)}
}

// InScope reports whether target (a txid_vout outpoint) is in origin's
// content scope, scanning and caching by (origin, latestOutpoint) if
// needed (decision 6). origin and latestOutpoint are always themselves in
// scope: they are the scan's roots, not something reachability needs to
// prove.
//
// R4: the shared, singleflighted scan runs under its own context, detached
// from whichever caller happens to trigger it (context.WithoutCancel) and
// bounded by its own timeout (scopeScanTimeout) rather than ctx's
// cancellation — so a caller disconnecting mid-scan can neither truncate
// the scan nor, by extension, ever poison the cache with a truncated
// result for every other caller sharing the same (origin, latestOutpoint)
// key. Only a complete scopeResult (scanScope's complete field) is ever
// stored in byKey; an incomplete one is still the right answer for the
// caller that's waiting on it right now, just never memoized.
func (c *scopeCache) InScope(ctx context.Context, origin, latestOutpoint, target string) bool {
	if target == origin || target == latestOutpoint {
		return true
	}
	key := origin + "|" + latestOutpoint

	c.mu.Lock()
	cached := c.byKey[key]
	c.mu.Unlock()
	if cached != nil {
		return cached.has(target)
	}

	v, _, _ := c.sf.Do(key, func() (interface{}, error) {
		c.mu.Lock()
		if cached := c.byKey[key]; cached != nil {
			c.mu.Unlock()
			return cached, nil
		}
		c.mu.Unlock()

		scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), scopeScanTimeout)
		defer cancel()
		result := scanScope(scanCtx, c.content, origin, latestOutpoint)
		if !result.complete {
			return result, nil
		}

		c.mu.Lock()
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

type frontierNode struct {
	outpoint string
	depth    int
}

// scanScope performs decision 6's breadth-first reachability scan from
// origin and latestOutpoint, bounded by depth, outpoint count and bytes
// fetched. Hitting any of those deterministic bounds simply stops
// expansion — everything found up to that point is a complete, correct
// (if conservative) scope, fit to cache (R4). Stopping because ctx is
// done (the scan's own bounded timeout — see InScope) is different:
// expansion is abandoned early, so the queue may still have held
// references this run never got to discover — the returned set is still
// the best answer available for the caller waiting on it right now, but
// it is marked incomplete, and InScope never caches an incomplete result.
// A per-node fetch error also marks the result incomplete (for the same
// caching reason) but does NOT stop the scan early: that node stays in
// scope (it WAS referenced), it just can't be scanned further for its own
// references, exactly as before — only the final caching decision changes.
func scanScope(ctx context.Context, content contentFetcher, origin, latestOutpoint string) *scopeResult {
	visited := map[string]struct{}{origin: {}, latestOutpoint: {}}
	// Queue each root once: B7a's DefaultVersions always has
	// latestOutpoint == origin (every site starts at seq 0 with no tip
	// tracking yet), and queuing the same outpoint twice would fetch and
	// count it twice against the byte budget for no benefit.
	queue := []frontierNode{{origin, 0}}
	if latestOutpoint != origin {
		queue = append(queue, frontierNode{latestOutpoint, 0})
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

// isScannableText reports whether contentType is one of decision 6's
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
