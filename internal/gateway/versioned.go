package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/BSVanon/Anvil/internal/content"
)

// scopeMaxVersionRoots bounds how many of an origin's earlier versions,
// the most recent first, root its content scope beside the origin and the
// latest version.
const scopeMaxVersionRoots = 500

// versionHistory is what a Versions that keeps a version history offers:
// every version outpoint of a tracked origin, oldest first, the origin
// first of all. The node's version tracker (internal/ordtrack) does.
type versionHistory interface {
	History(origin string) []string
}

// setVersionHistory makes every version of a site's origin up to the
// latest a root of the site's content scope, when versions keeps a history.
func (sh *SiteHandler) setVersionHistory(versions Versions) {
	if h, ok := versions.(versionHistory); ok {
		sh.scope.history = h.History
	}
}

// versionRoots returns origin's versions before latestOutpoint, newest
// first and at most scopeMaxVersionRoots of them, for the scan to root at
// beside the two. rooted is false when the history does not reach
// latestOutpoint, which happens only while the history changes; the scan
// is then not kept for long.
func (c *scopeCache) versionRoots(origin, latestOutpoint string) (versions []string, rooted bool) {
	if c.history == nil || latestOutpoint == origin {
		return nil, true
	}
	h := c.history(origin)
	end := slices.Index(h, latestOutpoint)
	if end < 0 {
		return nil, false
	}
	for i := end - 1; i >= 0 && len(versions) < scopeMaxVersionRoots; i-- {
		if h[i] != origin {
			versions = append(versions, h[i])
		}
	}
	return versions, true
}

// serveVersion answers either sequence form on a site host once locator is in
// the site's content scope. The response carries the same mirror headers as
// the rest of the site. Pending and shallow mappings use the root max-age.
func (sh *SiteHandler) serveVersion(w http.ResponseWriter, r *http.Request, locator string, seq int) {
	resolver, ok := sh.versions.(content.VersionResolver)
	if !ok {
		sh.counters.NotFound.Add(1)
		http.Error(w, content.ErrNotTracked.Error(), http.StatusNotFound)
		return
	}
	resolved, err := resolver.ResolveVersionAt(locator, seq)
	switch {
	case errors.Is(err, content.ErrNotTracked), errors.Is(err, content.ErrNoVersion):
		sh.counters.NotFound.Add(1)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		sh.logger.Warn("gateway version lookup failed", "origin", locator)
		http.Error(w, "version lookup failed", http.StatusBadGateway)
		return
	}
	txid, vout, ok := splitOutpoint(resolved.ContentOutpoint)
	if !ok {
		http.Error(w, "invalid version outpoint", http.StatusBadGateway)
		return
	}
	data, contentType, err := sh.content.Inscription(r.Context(), txid, vout)
	if err != nil {
		sh.logger.Warn("gateway content fetch failed", "txid", txid)
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	w.Header().Set(originHeader, resolved.Origin)
	w.Header().Set(outpointHeader, resolved.Outpoint)
	w.Header().Set(content.OrdSeqHeader, fmt.Sprintf("%d", resolved.Seq))
	w.Header().Set("Content-Type", contentType)
	switch {
	case seq == -1:
		w.Header().Set("Cache-Control", "no-store")
	case resolved.Immutable:
		w.Header().Set("Cache-Control", content.VersionImmutableCacheControl)
	default:
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(sh.rootMaxAge.Seconds())))
	}
	_, _ = w.Write(data)
}
