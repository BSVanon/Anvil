package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

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

// serveVersion answers /content/<origin>?seq= on a site host, once origin
// is known to be in the site's content scope: the version of origin that
// seq names, -1 being the latest, when the node tracks origin. The
// response carries the same mirror headers as the rest of the site, with
// origin and the outpoint served; a latest or not yet mined version is
// cacheable for the root max-age only, a mined one for good.
func (sh *SiteHandler) serveVersion(w http.ResponseWriter, r *http.Request, origin string) {
	seq, err := strconv.Atoi(r.URL.Query().Get("seq"))
	if err != nil || seq < -1 {
		http.Error(w, "invalid seq: want -1 or a version number", http.StatusBadRequest)
		return
	}
	resolver, ok := sh.versions.(content.VersionResolver)
	if !ok {
		sh.counters.NotFound.Add(1)
		http.Error(w, content.ErrNotTracked.Error(), http.StatusNotFound)
		return
	}
	outpoint, pending, err := resolver.ResolveVersion(origin, seq)
	switch {
	case errors.Is(err, content.ErrNotTracked), errors.Is(err, content.ErrNoVersion):
		sh.counters.NotFound.Add(1)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		sh.logger.Warn("gateway version lookup failed", "origin", origin)
		http.Error(w, "version lookup failed", http.StatusBadGateway)
		return
	}
	txid, vout, ok := splitOutpoint(outpoint)
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
	w.Header().Set(originHeader, origin)
	w.Header().Set(outpointHeader, outpoint)
	w.Header().Set("Content-Type", contentType)
	if seq == -1 || pending {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(sh.rootMaxAge.Seconds())))
	} else {
		w.Header().Set("Cache-Control", content.ImmutableCacheControl)
	}
	_, _ = w.Write(data)
}
