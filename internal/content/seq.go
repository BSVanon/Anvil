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
	OrdSeqHeader   = "X-Ord-Seq"
	// VersionImmutableCacheControl is used only after a tracked location is
	// mined at least six blocks deep on the node's best chain.
	VersionImmutableCacheControl = "public, max-age=31536000, immutable"
)

var (
	// ErrNotTracked is a VersionResolver's answer for an origin this node
	// does not track.
	ErrNotTracked = errors.New("origin not tracked by this node")
	// ErrNoVersion is its answer for a version number the origin does not
	// have (yet).
	ErrNoVersion = errors.New("no such version of this origin")
)

// VersionResolver resolves a tracked origin's spend locations: seq 0 is the
// origin, N is the Nth spend that has a resulting location, and -1 is the
// current location. contentOutpoint is the most recent inscription at or
// before that location. pending reports a location not yet mined.
type VersionResolver interface {
	ResolveVersion(origin string, seq int) (outpoint, contentOutpoint string, pending bool, err error)
	ResolveVersionAt(locator string, relativeSeq int) (VersionLocation, error)
}

// VersionLocation is one resolved location. Seq is counted from Origin even
// when the request started at a later locator. Immutable is true only when
// the location is mined at least six blocks deep on the best chain.
type VersionLocation struct {
	Origin          string
	Outpoint        string
	ContentOutpoint string
	Seq             int
	Pending         bool
	Immutable       bool
}

type versionHook struct {
	r           VersionResolver
	shortMaxAge time.Duration
}

// SetVersions makes the query and path sequence forms answer from r.
// shortMaxAge is used for pending, shallow, or not-provably-deep locations.
// Without r every sequence request answers that this node does not track the
// origin.
func (s *Server) SetVersions(r VersionResolver, shortMaxAge time.Duration) {
	if r == nil {
		s.versions.Store(nil)
		return
	}
	s.versions.Store(&versionHook{r: r, shortMaxAge: shortMaxAge})
}

// serveVersion answers both /content/<locator>?seq=N and
// /content/<locator>:N. N is relative to locator.
func (s *Server) serveVersion(w http.ResponseWriter, r *http.Request, rawLocator string, seq int) {
	locator, ok := versionOrigin(rawLocator)
	if !ok {
		http.Error(w, "invalid origin", http.StatusBadRequest)
		return
	}
	h := s.versions.Load()
	if h == nil {
		http.Error(w, ErrNotTracked.Error(), http.StatusNotFound)
		return
	}
	resolved, err := h.r.ResolveVersionAt(locator, seq)
	switch {
	case errors.Is(err, ErrNotTracked), errors.Is(err, ErrNoVersion):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "version lookup failed", http.StatusBadGateway)
		return
	}
	txid, vout, _ := strings.Cut(resolved.ContentOutpoint, "_")
	insc, status, err := s.inscriptionAt(txid, vout)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", defaultContentType(insc.ContentType))
	switch {
	case seq == -1:
		w.Header().Set("Cache-Control", "no-store")
	case resolved.Immutable:
		w.Header().Set("Cache-Control", VersionImmutableCacheControl)
	default:
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.shortMaxAge.Seconds())))
	}
	w.Header().Set(OriginHeader, resolved.Origin)
	w.Header().Set(OutpointHeader, resolved.Outpoint)
	w.Header().Set(OrdSeqHeader, strconv.Itoa(resolved.Seq))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	expose := OriginHeader + ", " + OutpointHeader + ", " + OrdSeqHeader
	if prev := w.Header().Get("Access-Control-Expose-Headers"); prev != "" {
		expose = prev + ", " + expose
	}
	w.Header().Set("Access-Control-Expose-Headers", expose)
	_, _ = w.Write(insc.Data)
}

// SplitVersionLocator separates the optional :seq suffix accepted beside the
// seq query form. It does not validate the outpoint portion.
func SplitVersionLocator(raw string) (locator string, seq int, hasSeq bool, err error) {
	i := strings.LastIndexByte(raw, ':')
	if i < 0 {
		return raw, 0, false, nil
	}
	if i == 0 || i == len(raw)-1 || strings.ContainsRune(raw[:i], ':') {
		return "", 0, true, errors.New("invalid version locator")
	}
	seq, err = strconv.Atoi(raw[i+1:])
	if err != nil || seq < -1 {
		return "", 0, true, errors.New("invalid version sequence")
	}
	return raw[:i], seq, true, nil
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
