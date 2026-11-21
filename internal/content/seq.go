package content

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The mirror headers a versioned response carries: the origin asked for
// and the exact outpoint served. The gateway's site handler sends the same
// two.
const (
	OriginHeader   = "X-Origin"
	OutpointHeader = "X-Outpoint"
)

var (
	// ErrNotTracked is a VersionResolver's answer for an origin this node
	// does not track.
	ErrNotTracked = errors.New("origin not tracked by this node")
	// ErrNoVersion is its answer for a version number the origin does not
	// have (yet).
	ErrNoVersion = errors.New("no such version of this origin")
)

// VersionResolver resolves a tracked origin's versions, BRC-159 links that
// carry a BRC-160 inscription: seq 0 is the origin, N the Nth inscribed
// link after it, -1 the latest. pending reports a version whose
// transaction is not yet mined.
type VersionResolver interface {
	ResolveVersion(origin string, seq int) (outpoint string, pending bool, err error)
}

type versionHook struct {
	r           VersionResolver
	shortMaxAge time.Duration
}

// SetVersions makes GET /content/<origin>?seq= answer from r. Responses
// for seq -1, and for a version not yet mined, are cacheable for
// shortMaxAge only; a mined version's are immutable. Without it every
// ?seq request answers that this node does not track the origin.
func (s *Server) SetVersions(r VersionResolver, shortMaxAge time.Duration) {
	if r == nil {
		s.versions.Store(nil)
		return
	}
	s.versions.Store(&versionHook{r: r, shortMaxAge: shortMaxAge})
}

// serveVersion answers GET /content/<origin>?seq=N.
func (s *Server) serveVersion(w http.ResponseWriter, r *http.Request) {
	origin, ok := versionOrigin(r.PathValue("origin"))
	if !ok {
		http.Error(w, "invalid origin", http.StatusBadRequest)
		return
	}
	seq, err := strconv.Atoi(r.URL.Query().Get("seq"))
	if err != nil || seq < -1 {
		http.Error(w, "invalid seq: want -1 or a version number", http.StatusBadRequest)
		return
	}
	h := s.versions.Load()
	if h == nil {
		http.Error(w, ErrNotTracked.Error(), http.StatusNotFound)
		return
	}
	outpoint, pending, err := h.r.ResolveVersion(origin, seq)
	switch {
	case errors.Is(err, ErrNotTracked), errors.Is(err, ErrNoVersion):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "version lookup failed", http.StatusBadGateway)
		return
	}
	txid, vout, _ := strings.Cut(outpoint, "_")
	insc, status, err := s.inscriptionAt(txid, vout)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", defaultContentType(insc.ContentType))
	if seq == -1 || pending {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.shortMaxAge.Seconds())))
	} else {
		w.Header().Set("Cache-Control", ImmutableCacheControl)
	}
	w.Header().Set(OriginHeader, origin)
	w.Header().Set(OutpointHeader, outpoint)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	expose := OriginHeader + ", " + OutpointHeader
	if prev := w.Header().Get("Access-Control-Expose-Headers"); prev != "" {
		expose = prev + ", " + expose
	}
	w.Header().Set("Access-Control-Expose-Headers", expose)
	_, _ = w.Write(insc.Data)
}

// versionOrigin normalizes a path's "txid" or "txid_vout" to "txid_vout".
func versionOrigin(raw string) (string, bool) {
	txid, vout, hasVout := strings.Cut(raw, "_")
	if !hasVout {
		vout = "0"
	}
	if len(txid) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(txid); err != nil {
		return "", false
	}
	n, err := strconv.ParseUint(vout, 10, 32)
	if err != nil {
		return "", false
	}
	return strings.ToLower(txid) + "_" + strconv.FormatUint(n, 10), true
}

// inscriptionAt is ServeContent's cache, fetch and parse for one outpoint,
// with the status ServeContent answers each failure with.
func (s *Server) inscriptionAt(txid, vout string) (*inscription, int, error) {
	key := txid + "_" + vout
	s.mu.RLock()
	cached, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Since(cached.FetchedAt) < s.maxAge {
		return cached, http.StatusOK, nil
	}
	rawHex, err := s.fetchRawTx(txid)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("fetch tx: %w", err)
	}
	insc, err := parseInscription(rawHex, vout)
	if err != nil {
		return nil, http.StatusNotFound, fmt.Errorf("parse inscription: %w", err)
	}
	s.storeInscription(key, insc)
	return insc, http.StatusOK, nil
}

// RawTx returns txid's raw transaction through the content fetch path:
// the block cache, a P2P fetch, then WhatsOnChain, each answer checked to
// hash to txid. ctx is only checked before the fetch starts.
func (s *Server) RawTx(ctx context.Context, txid string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(txid) != 64 {
		return nil, fmt.Errorf("invalid txid")
	}
	rawHex, err := s.fetchRawTx(strings.ToLower(txid))
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(rawHex))
}
