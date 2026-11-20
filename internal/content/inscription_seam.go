package content

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// ImmutableCacheControl is the Cache-Control value ServeContent sends for
// a txid-addressed outpoint — immutable, because the exact bytes at a
// given outpoint can never change. The gateway mechanism
// (internal/gateway's site handler) reuses this literal value for its own
// "/content/<txid>_<vout>" responses, so both paths stay byte-identical on
// this header without copying the string.
const ImmutableCacheControl = "public, max-age=86400, immutable"

// storeInscription caches insc under cacheKey, evicting the oldest entry
// if the cache has grown past its bound. Shared by ServeContent and
// Inscription so there is exactly one eviction policy for this cache.
func (s *Server) storeInscription(cacheKey string, insc *inscription) {
	s.mu.Lock()
	s.cache[cacheKey] = insc
	// Evict old entries if cache grows too large
	if len(s.cache) > 10000 {
		oldest := ""
		oldestTime := time.Now()
		for k, v := range s.cache {
			if v.FetchedAt.Before(oldestTime) {
				oldest = k
				oldestTime = v.FetchedAt
			}
		}
		if oldest != "" {
			delete(s.cache, oldest)
		}
	}
	s.mu.Unlock()
}

// Inscription returns the parsed on-chain content at txid_vout — its bytes
// and declared content type — fetching and caching exactly as ServeContent
// does: the same txid check, the same fetchRawTx, the same cache (so a hit
// warmed by one caller serves the other). It has no http.ResponseWriter,
// so the gateway mechanism (internal/gateway) uses it to serve a custom
// domain's "/" and "/content/..." and to walk content scope's reference
// graph, all against the one cache this package already keeps warm.
//
// ctx is only checked before any work starts — fails fast on an
// already-canceled context — because the underlying fetch (fetchRawTx) has
// no per-call cancellation of its own yet.
func (s *Server) Inscription(ctx context.Context, txid string, vout int) (data []byte, contentType string, err error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if len(txid) != 64 {
		return nil, "", fmt.Errorf("invalid txid")
	}
	if vout < 0 {
		return nil, "", fmt.Errorf("invalid vout")
	}
	voutStr := strconv.Itoa(vout)
	cacheKey := txid + "_" + voutStr

	s.mu.RLock()
	cached, ok := s.cache[cacheKey]
	s.mu.RUnlock()
	if ok && time.Since(cached.FetchedAt) < s.maxAge {
		return cached.Data, defaultContentType(cached.ContentType), nil
	}

	rawHex, err := s.fetchRawTx(txid)
	if err != nil {
		return nil, "", fmt.Errorf("fetch tx: %w", err)
	}

	insc, err := parseInscription(rawHex, voutStr)
	if err != nil {
		return nil, "", fmt.Errorf("parse inscription: %w", err)
	}

	s.storeInscription(cacheKey, insc)

	return insc.Data, defaultContentType(insc.ContentType), nil
}

// defaultContentType mirrors serveInscription's fallback so every caller —
// ServeContent's HTTP response and Inscription's return value — treats a
// missing declared content type the same way.
func defaultContentType(ct string) string {
	if ct == "" {
		return "application/octet-stream"
	}
	return ct
}
