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
// goroutine, where nothing can recover it. The GASP remote decodes a JSON
// stream that need never end.
//
// Install wraps DefaultClient's transport. Every response body is then capped
// at MaxResponseBytes, and every reply to an overlay lookup is read in full,
// up to peerhygiene.MaxLookupResponseBytes, and handed on only once
// peerhygiene.ValidateLookupAnswer accepts it.
package netguard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
)

// MaxResponseBytes caps every response body read through http.DefaultClient.
// It is the cap Anvil puts on an inbound /submit or /lookup body (the overlay
// handlers' 64 MiB default), so a peer can make this node read no more than
// it could make the node accept. The largest honest replies on these paths are
// far smaller. A GASP /requestSyncResponse lists about 110 bytes per UTXO, so
// 64 MiB holds some 600,000 UTXOs of one topic. A /requestForeignGASPNode
// carries one transaction in hex with its proof, so 64 MiB covers transactions
// up to 32 MiB. A /submit STEAK is a few hundred bytes. Lookup replies have
// their own, smaller cap.
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
		}
	})
}

// guard is the http.RoundTripper Install puts on http.DefaultClient.
type guard struct {
	base           http.RoundTripper
	maxBytes       int64
	maxLookupBytes int64
}

// RoundTrip sends req through the base transport and bounds the response. A
// 101 Switching Protocols response and the reply to a HEAD request have no
// body to bound and pass through untouched.
func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := g.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusSwitchingProtocols || req.Method == http.MethodHead {
		return resp, nil
	}
	if resp.StatusCode == http.StatusOK && isLookup(req) {
		return g.checkLookup(resp)
	}
	if resp.ContentLength > g.maxBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: Content-Length %d is over %d bytes", ErrResponseTooLarge, resp.ContentLength, g.maxBytes)
	}
	resp.Body = &cappedBody{rc: resp.Body, left: g.maxBytes, max: g.maxBytes}
	return resp, nil
}

// isLookup reports whether req belongs to an overlay lookup: a POST to a URL
// that the lookup facilitators build as host + "/lookup", which they mark with
// X-Aggregation. The URL is matched as a whole string, because a hostile
// advertised host such as "https://h/x?" puts "/lookup" in the query, not the
// path. A redirect's follow-up request is judged by the request that started
// the exchange, since the client hands the final response to the facilitator
// whatever URL and method fetched it.
func isLookup(req *http.Request) bool {
	for req.Response != nil && req.Response.Request != nil {
		req = req.Response.Request
	}
	if req.Method != http.MethodPost {
		return false
	}
	return req.Header.Get("X-Aggregation") != "" ||
		strings.HasSuffix(req.URL.Path, "/lookup") ||
		strings.HasSuffix(req.URL.String(), "/lookup")
}

// checkLookup reads a lookup reply in full, up to maxLookupBytes, and hands it
// on only if peerhygiene.ValidateLookupAnswer accepts it, as a fresh body of
// the same bytes. Otherwise the original body is closed and RoundTrip fails,
// so go-sdk's facilitator never parses the reply.
func (g *guard) checkLookup(resp *http.Response) (*http.Response, error) {
	body, err := readLookupBody(resp, g.maxLookupBytes)
	if err != nil {
		return nil, err
	}
	if err := peerhygiene.ValidateLookupAnswer(resp.Header.Get("Content-Type"), body); err != nil {
		return nil, fmt.Errorf("netguard: rejected lookup answer: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.TransferEncoding = nil
	return resp, nil
}

// readLookupBody reads resp's whole body, failing once it passes max bytes,
// and always closes it.
func readLookupBody(resp *http.Response, max int64) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength > max {
		return nil, fmt.Errorf("%w: lookup Content-Length %d is over %d bytes", ErrResponseTooLarge, resp.ContentLength, max)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("netguard: reading lookup answer: %w", err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%w: lookup body is over %d bytes", ErrResponseTooLarge, max)
	}
	return body, nil
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
