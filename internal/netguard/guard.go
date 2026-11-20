// Package netguard bounds what any response read through http.DefaultClient
// can cost the node.
//
// Libraries the node runs reach on-chain-advertised peers, any of which may be
// hostile, through http.DefaultClient, and give Anvil no way to pass them
// another client:
//
//   - go-overlay-services v1.3.1 builds a fresh go-sdk LookupResolver, with the
//     default HTTPSOverlayLookupFacilitator, every time it propagates an
//     admitted /submit (engine.go propagateToNetwork), plus a topic Broadcaster
//     whose default facilitator POSTs the transaction to each interested host.
//   - its GASP remote fetches /requestSyncResponse and /requestForeignGASPNode
//     from SHIP-advertised peers (engine.go syncWithPeer and
//     syncMerkleProofFromPeers);
//   - its default engine LookupResolver and Anvil's peerhygiene resolver also
//     read through it.
//
// Those readers trust what they read. go-sdk's lookup facilitator reads the
// whole body and sizes allocations from counts inside it, so a 9-byte reply is
// a fatal out-of-memory error and a 43-byte one a panic in the resolver's
// goroutine, where nothing can recover it. Its broadcast facilitator decodes a
// /submit reply into a STEAK whose nil entries the Broadcaster then
// dereferences (topic/broadcaster.go:177-178), so a 4-byte "null" is a panic.
// The GASP remote decodes a JSON stream that need never end.
//
// Install wraps DefaultClient's transport. Every response body is then capped
// at MaxResponseBytes. A lookup or GASP exchange's response headers must
// arrive within HeaderTimeout of the request, or it is cancelled; a 101
// Switching Protocols reply is refused outright unless the request itself
// asked for the upgrade, since net/http hands an upgraded reply's body on as
// the raw, unbounded connection (cold review round 4 cycle 6b, RISK 1, B2).
// Every reply to an overlay lookup is read in full, up to
// peerhygiene.MaxLookupResponseBytes, under one of bodyread.LookupPermits read
// permits, and only then validated and decoded under one of
// peerhygiene.LookupSlots decoding slots, shared with
// peerhygiene.BoundedFacilitator: however many hosts answer at once, and
// however slowly, no more than that many replies are being read and no more
// than that many answers decoded. Every POST to a /submit endpoint is one
// exchange of at most SubmitTimeout, and its STEAK reply is read up to
// MaxSteakBytes, validated, and handed on re-encoded, so go-sdk decodes
// exactly what was checked. Every reply to a GASP node fetch
// (/requestForeignGASPNode) or initial sync request (/requestSyncResponse) is
// read in full, up to MaxResponseBytes -- the cap this traffic already had --
// under gaspReadTimeout's size-scaled deadline and the same minimum rate a
// lookup reply reads under. A GASP node reply is then decoded exactly as
// go-overlay-services' own doNodeRequest decodes it, refused if it does not
// decode that way or if its transaction has an unlocking script the B1
// reparse bug (cold review round 4) could reach, and otherwise handed on as
// exactly the bytes decoded, never re-encoded (cold review round 4 cycle 6b's
// own B1: re-encoding a string field padded with '<', '>' or '&' can grow it
// 6x under json.Marshal's HTML-escaping); see checkGASPNode. A sync reply has
// no transaction to check and is handed on as read; see checkGASPSync.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
)

// MaxResponseBytes caps every response body read through http.DefaultClient.
// It is the cap Anvil puts on an inbound /submit or /lookup body (the overlay
// handlers' 64 MiB default), so a peer can make this node read no more than
// it could make the node accept. The largest honest replies on these paths are
// far smaller. A GASP /requestSyncResponse lists about 110 bytes per UTXO, so
// 64 MiB holds some 600,000 UTXOs of one topic. A /requestForeignGASPNode
// carries one transaction in hex with its proof, so 64 MiB covers transactions
// up to 32 MiB. Lookup and /submit replies have their own, smaller caps.
const MaxResponseBytes int64 = 64 << 20

// ErrResponseTooLarge is returned, from RoundTrip or from a body Read, for a
// response whose body is over its cap. An over-cap body is always an error,
// never a silent truncation.
var ErrResponseTooLarge = errors.New("netguard: response body exceeds size cap")

var installOnce sync.Once

// Install wraps http.DefaultClient's transport in the guard. It changes the
// existing client object rather than replacing the variable, so code that
// captured the http.DefaultClient pointer before Install is covered too. It
// does not touch http.DefaultTransport, so clients built with a transport of
// their own are unaffected. Install is idempotent. It must run before any
// goroutine uses http.DefaultClient: at node start-up, ahead of the overlay
// engine and every resolver.
func Install() {
	installOnce.Do(func() {
		base := http.DefaultClient.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		http.DefaultClient.Transport = &guard{
			base:           base,
			maxBytes:       MaxResponseBytes,
			maxLookupBytes: peerhygiene.MaxLookupResponseBytes,
			readTimeout:    peerhygiene.LookupReadTimeout,
			minRate:        bodyread.MinReadRate,
			grace:          bodyread.ReadGrace,
			maxSteakBytes:  MaxSteakBytes,
			submitTimeout:  SubmitTimeout,
		}
	})
}

// HeaderTimeout bounds how long a lookup or GASP exchange may wait for
// response headers, from sending the request (cold review round 4 cycle 6b,
// RISK 1): before this, only the body read had a deadline, so a peer that
// never sent headers at all, or a redirect hop that never answered, blocked
// that exchange forever -- and GASP sync runs one peer and topic at a time
// on the root context, so one such peer froze every later one too.
const HeaderTimeout = 30 * time.Second

// guard is the http.RoundTripper Install puts on http.DefaultClient.
type guard struct {
	base           http.RoundTripper
	maxBytes       int64
	maxLookupBytes int64
	readTimeout    time.Duration // how long reading one lookup reply's body may take; GASP's own deadline is gaspReadTimeout, not this field
	minRate        int64         // bytes/s a lookup, GASP or STEAK reply must keep up after grace; zero for no floor
	grace          time.Duration
	maxSteakBytes  int64         // zero or less uses MaxSteakBytes
	submitTimeout  time.Duration // one /submit exchange; zero or less uses SubmitTimeout
	headerTimeout  time.Duration // zero or less uses HeaderTimeout
}

func (g *guard) headerDeadline() time.Duration {
	if g.headerTimeout <= 0 {
		return HeaderTimeout
	}
	return g.headerTimeout
}

// withinHeaderDeadline sends req through g.base, cancelling the wait if
// response headers do not arrive within g.headerDeadline(). Once headers
// arrive the timer is disarmed and its cancel is instead released when the
// response body is closed (the same shape roundTripSubmit's cancelOnClose
// gives a /submit exchange's deadline), so a body that keeps arriving, just
// slowly, is never cut short by this timer -- that is bodyread's job, under
// its own, separate and longer deadline. Leaks no goroutine: the context's
// own cancel is always eventually called, whether by the timer, by this
// function on an error, or by the wrapped body's Close.
func (g *guard) withinHeaderDeadline(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	timer := time.AfterFunc(g.headerDeadline(), cancel)
	resp, err := g.base.RoundTrip(req.WithContext(ctx))
	timer.Stop()
	if err != nil || resp == nil {
		cancel()
		return resp, err
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// requestedUpgrade reports whether req itself asked for a protocol upgrade:
// a non-empty Upgrade header and an "upgrade" token in Connection, the pair
// every real upgrade request sets and no request any guarded call site here
// sends (lookup, GASP and /submit are all plain POSTs). See RoundTrip's 101
// handling.
func requestedUpgrade(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, tok := range strings.Split(req.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// RoundTrip sends req through the base transport and bounds the response.
// The reply to a HEAD request has no body to bound and passes through
// untouched. A 101 Switching Protocols response hands the caller the raw,
// unbounded connection as its body (net/http's own transport special-cases
// it); that is only safe when req itself asked for the upgrade, so an
// unrequested one is refused outright instead (cold review round 4 cycle 6b,
// B2: go-overlay-services' GASP client reads any non-200 reply's body in
// full with no cap, so an unrequested 101 from a SHIP-advertised peer, with
// Connection: Upgrade set on the reply alone, let that peer stream without
// limit). A /submit exchange is bounded as a whole by roundTripSubmit. A
// lookup or GASP exchange's response headers are bounded by
// withinHeaderDeadline before the base transport is even asked (RISK 1);
// their 200 replies are read, decoded (GASP nodes only) and re-bounded by
// checkLookup, checkGASPNode or checkGASPSync.
func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if isSubmit(req) {
		return g.roundTripSubmit(req)
	}
	headerBound := isLookup(req) || isGASPNode(req) || isGASPSync(req)
	var resp *http.Response
	var err error
	if headerBound {
		resp, err = g.withinHeaderDeadline(req)
	} else {
		resp, err = g.base.RoundTrip(req)
	}
	if err != nil || resp == nil {
		return resp, err
	}
	if req.Method == http.MethodHead {
		return resp, nil
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if requestedUpgrade(req) {
			return resp, nil
		}
		_ = resp.Body.Close()
		return nil, errors.New("netguard: refused a 101 Switching Protocols reply to a request that did not ask for one")
	}
	if resp.StatusCode == http.StatusOK && isLookup(req) {
		return g.checkLookup(req, resp)
	}
	if resp.StatusCode == http.StatusOK && isGASPNode(req) {
		return g.checkGASPNode(resp)
	}
	if resp.StatusCode == http.StatusOK && isGASPSync(req) {
		return g.checkGASPSync(resp)
	}
	if resp.ContentLength > g.maxBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: Content-Length %d is over %d bytes", ErrResponseTooLarge, resp.ContentLength, g.maxBytes)
	}
	resp.Body = &cappedBody{rc: resp.Body, left: g.maxBytes, max: g.maxBytes}
	return resp, nil
}

// origin is the request that started req's exchange: req itself, or, for a
// redirect's follow-up, the first request of the chain. The client hands the
// final response to the caller whatever URL and method fetched it, so every
// hop is judged by the origin.
func origin(req *http.Request) *http.Request {
	for req.Response != nil && req.Response.Request != nil {
		req = req.Response.Request
	}
	return req
}

// isLookup reports whether req belongs to an overlay lookup: a POST to a URL
// that the lookup facilitators build as host + "/lookup", which they mark with
// X-Aggregation. The URL is matched as a whole string, because a hostile
// advertised host such as "https://h/x?" puts "/lookup" in the query, not the
// path. A redirect's follow-up request is judged by its origin.
func isLookup(req *http.Request) bool {
	req = origin(req)
	if req.Method != http.MethodPost {
		return false
	}
	return req.Header.Get("X-Aggregation") != "" ||
		strings.HasSuffix(req.URL.Path, "/lookup") ||
		strings.HasSuffix(req.URL.String(), "/lookup")
}

// isSubmit reports whether req belongs to an overlay submit, by the rules
// isLookup uses: a POST to a URL that go-sdk's broadcast facilitator builds
// as host + "/submit", which it marks with X-Topics, judged by its origin. A
// lookup is never a submit.
func isSubmit(req *http.Request) bool {
	if isLookup(req) {
		return false
	}
	req = origin(req)
	if req.Method != http.MethodPost {
		return false
	}
	return req.Header.Get("X-Topics") != "" ||
		strings.HasSuffix(req.URL.Path, "/submit") ||
		strings.HasSuffix(req.URL.String(), "/submit")
}

// cappedBody passes a response body through until more than max bytes would
// have been read, then fails with ErrResponseTooLarge, like
// http.MaxBytesReader does for request bodies.
type cappedBody struct {
	rc   io.ReadCloser
	left int64 // bytes still allowed
	max  int64
	err  error // sticky: the first error, including io.EOF
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// One byte past the allowance tells reaching the cap from going over it.
	if int64(len(p))-1 > b.left {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	if int64(n) <= b.left {
		b.left -= int64(n)
		b.err = err
		return n, err
	}
	n = int(b.left)
	b.left = 0
	b.err = fmt.Errorf("%w: body is over %d bytes", ErrResponseTooLarge, b.max)
	return n, b.err
}

func (b *cappedBody) Close() error { return b.rc.Close() }
