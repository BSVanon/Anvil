package gateway

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"
)

// Decision 6's scan bounds.
const (
	scopeMaxDepth     = 4
	scopeMaxOutpoints = 2000
	scopeMaxBytes     = 32 << 20 // 32 MiB
)

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

// scopeResult is one scan's reachable outpoint set.
type scopeResult struct {
	set map[string]struct{}
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

		result := scanScope(ctx, c.content, origin, latestOutpoint)

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
// fetched. Hitting a bound simply stops expansion — everything found up
// to that point is still a valid (if conservative) scope. A fetch failure
// for a referenced outpoint also just stops expansion from that node: it
// was still referenced (so it stays in scope), it just can't be scanned
// further for its own references.
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

	for len(queue) > 0 && len(visited) < scopeMaxOutpoints && bytesFetched < scopeMaxBytes {
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
	return &scopeResult{set: visited}
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
