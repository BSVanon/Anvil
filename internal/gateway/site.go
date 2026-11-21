package gateway

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/clientkey"
	"github.com/BSVanon/Anvil/internal/content"
)

// originHeader/outpointHeader are decision 5's mirror headers. A HEAD
// request against a public ordinals gateway
// (https://ordinals.gorillapool.io/content/<origin>?seq=-1, checked
// 2026-11-20) returned only standard/CDN headers — date, content-type,
// content-length, server, x-powered-by, vary, cache-control, etag,
// cf-cache-status, report-to, nel, cf-ray — no origin or outpoint header
// of its own to reuse, so this uses decision 5's fallback names.
const (
	originHeader   = "X-Origin"
	outpointHeader = "X-Outpoint"
)

// SiteHandlerConfig constructs a SiteHandler.
type SiteHandlerConfig struct {
	Policy *Policy
	// Content must be the node's existing content server
	// (srv.ContentServer(), internal/api's hook) so sites are served from
	// the same warm cache /content/ already uses.
	Content        contentFetcher
	Versions       Versions // nil defaults to DefaultVersions{}
	RootMaxAge     time.Duration
	ContentScope   string // "site" (default) or "any" — decision 6
	TrustProxy     bool
	TrustProxyHops int
	Counters       *Counters // default a fresh, unshared Counters
	Logger         *slog.Logger
}

// SiteHandler serves a publisher's own domain (decision 5): "/" (the
// latest version) and "/content/<txid>_<vout>" (an exact, immutable
// outpoint), subject to Policy and the content scope (decision 6), with
// per-client rate limiting (decision 8) and no per-request logging of
// anything but a fetch-failed txid (decision 8). It also implements
// decision 2's "anything else: a plain 404" for any Host that Policy
// refuses — Router delegates every non-API-host request here unconditionally.
type SiteHandler struct {
	policy     *Policy
	content    contentFetcher
	versions   Versions
	scope      *scopeCache
	limiter    *limiter
	counters   *Counters
	logger     *slog.Logger
	rootMaxAge time.Duration
	scopeAny   bool
	trustProxy bool
	trustHops  int
}

// NewSiteHandler builds a SiteHandler from cfg.
func NewSiteHandler(cfg SiteHandlerConfig) *SiteHandler {
	versions := cfg.Versions
	if versions == nil {
		versions = DefaultVersions{}
	}
	if cfg.RootMaxAge <= 0 {
		cfg.RootMaxAge = 60 * time.Second
	}
	if cfg.Counters == nil {
		cfg.Counters = &Counters{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	sh := &SiteHandler{
		policy:     cfg.Policy,
		content:    cfg.Content,
		versions:   versions,
		scope:      newScopeCache(cfg.Content),
		limiter:    newLimiter(siteTrafficRate, siteTrafficBurst),
		counters:   cfg.Counters,
		logger:     cfg.Logger,
		rootMaxAge: cfg.RootMaxAge,
		scopeAny:   cfg.ContentScope == "any",
		trustProxy: cfg.TrustProxy,
		trustHops:  cfg.TrustProxyHops,
	}
	sh.setVersionHistory(versions)
	return sh
}

// Stats returns the aggregate counters, ready for internal/api's
// SetGatewayStats hook (decision 8).
func (sh *SiteHandler) Stats() map[string]int64 {
	return sh.counters.Snapshot()
}

// ServeHTTP implements http.Handler.
func (sh *SiteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Decision 5: every site response, success or error, carries this.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	sh.counters.Requests.Add(1)

	host := normalizeHost(r.Host)
	origin, ok := sh.policy.Allowed(r.Context(), host)
	if !ok {
		sh.counters.NotFound.Add(1)
		http.NotFound(w, r)
		return
	}

	key := clientkey.Key(clientkey.IP(r, sh.trustProxy, sh.trustHops))
	if !sh.limiter.Allow(key) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	switch {
	case r.URL.Path == "/" && r.URL.Query().Has("seq"):
		// A version is asked for as /content/<origin>?seq= (serveVersion).
		// "/" with a seq is not served, and must not fall through to "/"'s
		// plain latest-version behaviour below.
		sh.counters.NotFound.Add(1)
		http.NotFound(w, r)
	case r.URL.Path == "/":
		sh.serveRoot(w, r, origin)
	case strings.HasPrefix(r.URL.Path, "/content/"):
		sh.serveContentPath(w, r, origin)
	default:
		sh.counters.NotFound.Add(1)
		http.NotFound(w, r)
	}
}

// serveRoot implements decision 5's "/": the latest version, with a
// short max-age, an ETag honouring If-None-Match, and the mirror headers.
func (sh *SiteHandler) serveRoot(w http.ResponseWriter, r *http.Request, origin string) {
	outpoint, err := sh.versions.Latest(origin)
	if err != nil {
		sh.logger.Warn("gateway latest version lookup failed", "origin", origin)
		http.Error(w, "latest version unavailable", http.StatusBadGateway)
		return
	}

	etag := `"` + outpoint + `"`
	w.Header().Set("ETag", etag)
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	txid, vout, ok := splitOutpoint(outpoint)
	if !ok {
		http.Error(w, "invalid version outpoint", http.StatusBadGateway)
		return
	}
	data, contentType, err := sh.content.Inscription(r.Context(), txid, vout)
	if err != nil {
		// Decision 8: content-fetch errors log the txid only.
		sh.logger.Warn("gateway content fetch failed", "txid", txid)
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}

	w.Header().Set(originHeader, origin)
	w.Header().Set(outpointHeader, outpoint)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(sh.rootMaxAge.Seconds())))
	_, _ = w.Write(data)
}

// serveContentPath implements decision 5's "/content/<txid>_<vout>",
// subject to decision 6's content scope.
//
// With ?seq, the outpoint is an origin, and the version of it that seq
// names is served instead.
func (sh *SiteHandler) serveContentPath(w http.ResponseWriter, r *http.Request, origin string) {
	target := strings.TrimPrefix(r.URL.Path, "/content/")
	locator, pathSeq, hasPathSeq, pathErr := content.SplitVersionLocator(target)
	if pathErr != nil || (hasPathSeq && r.URL.Query().Has("seq")) {
		http.Error(w, "invalid seq: want -1 or a version number", http.StatusBadRequest)
		return
	}
	seq := pathSeq
	versioned := hasPathSeq || r.URL.Query().Has("seq")
	if !hasPathSeq && r.URL.Query().Has("seq") {
		var err error
		seq, err = strconv.Atoi(r.URL.Query().Get("seq"))
		if err != nil || seq < -1 {
			http.Error(w, "invalid seq: want -1 or a version number", http.StatusBadRequest)
			return
		}
	}
	outpoint, ok := parseOutpoint(locator)
	if !ok {
		sh.counters.NotFound.Add(1)
		http.NotFound(w, r)
		return
	}

	if !sh.scopeAny {
		latest, err := sh.versions.Latest(origin)
		if err != nil {
			sh.logger.Warn("gateway latest version lookup failed", "origin", origin)
			http.Error(w, "latest version unavailable", http.StatusBadGateway)
			return
		}
		if !sh.scope.InScope(r.Context(), origin, latest, outpoint) {
			sh.counters.ScopeRefused.Add(1)
			http.NotFound(w, r)
			return
		}
	}
	if versioned {
		sh.serveVersion(w, r, outpoint, seq)
		return
	}

	txid, vout, ok := splitOutpoint(outpoint)
	if !ok {
		sh.counters.NotFound.Add(1)
		http.NotFound(w, r)
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
	w.Header().Set("Cache-Control", content.ImmutableCacheControl)
	_, _ = w.Write(data)
}

// etagMatches reports whether header (an If-None-Match value, possibly a
// comma-separated list, or "*") matches etag.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		if strings.TrimSpace(part) == etag {
			return true
		}
	}
	return false
}
