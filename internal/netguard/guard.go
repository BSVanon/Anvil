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
// peerhygiene.ValidateLookupAnswer accepts it. A lookup reply is read,
// validated and decoded under one of peerhygiene.LookupSlots decoding slots,
// shared with peerhygiene.BoundedFacilitator, so however many hosts answer at
// once, no more than that many answers are being decoded.
package netguard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
			readTimeout:    peerhygiene.LookupReadTimeout,
		}
	})
}

// guard is the http.RoundTripper Install puts on http.DefaultClient.
type guard struct {
	base           http.RoundTripper
	maxBytes       int64
	maxLookupBytes int64
	readTimeout    time.Duration // how long reading a lookup reply may hold its slot
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
		return g.checkLookup(req, resp)
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

// checkLookup takes a decoding slot, reads a lookup reply in full, up to
// maxLookupBytes, and hands it on only if peerhygiene.ValidateLookupAnswer
// accepts it, as a fresh body of the same bytes that keeps the slot until it is
// closed. go-sdk's facilitator closes the body only after decoding the answer,
// so the slot covers its decoding too. Otherwise the slot is returned, the
// original body is closed and RoundTrip fails, so go-sdk's facilitator never
// parses the reply.
func (g *guard) checkLookup(req *http.Request, resp *http.Response) (*http.Response, error) {
	release, err := peerhygiene.AcquireLookupSlot(req.Context())
	if err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("netguard: %w", err)
	}
	peerhygiene.MarkLookupSlotHeld(req.Context())
	body, err := readLookupBody(resp, g.maxLookupBytes, g.readTimeout)
	if err == nil {
		if verr := peerhygiene.ValidateLookupAnswer(resp.Header.Get("Content-Type"), body); verr != nil {
			err = fmt.Errorf("netguard: rejected lookup answer: %w", verr)
		}
	}
	if err != nil {
		release()
		return nil, err
	}
	resp.Body = newSlotBody(body, release)
	resp.ContentLength = int64(len(body))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.TransferEncoding = nil
	return resp, nil
}

// readLookupBody reads resp's whole body, failing once it passes max bytes or
// once timeout has passed, and always closes it, exactly once: from the timer,
// to cut a stalled read short, or else on return. The two never close it at
// the same time.
func readLookupBody(resp *http.Response, max int64, timeout time.Duration) ([]byte, error) {
	var closeOnce sync.Once
	closeBody := func() { closeOnce.Do(func() { _ = resp.Body.Close() }) }
	defer closeBody()
	if resp.ContentLength > max {
		return nil, fmt.Errorf("%w: lookup Content-Length %d is over %d bytes", ErrResponseTooLarge, resp.ContentLength, max)
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		timedOut.Store(true)
		closeBody()
	})
	defer timer.Stop()
	var body []byte
	var err error
	if resp.ContentLength >= 0 {
		// The length is known: one exact allocation instead of io.ReadAll's
		// growing copies. The transport ends the body at Content-Length.
		body = make([]byte, resp.ContentLength)
		_, err = io.ReadFull(resp.Body, body)
	} else {
		body, err = io.ReadAll(io.LimitReader(resp.Body, max+1))
	}
	if err != nil {
		if timedOut.Load() {
			return nil, fmt.Errorf("netguard: lookup answer not read within %v", timeout)
		}
		return nil, fmt.Errorf("netguard: reading lookup answer: %w", err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("%w: lookup body is over %d bytes", ErrResponseTooLarge, max)
	}
	return body, nil
}

// slotBody is a validated lookup answer handed on to the caller. It holds the
// answer's decoding slot until Close, however often Close is called. A body
// dropped without Close returns the slot once the garbage collector finds it
// unreachable.
type slotBody struct {
	*bytes.Reader
	release func()
}

func newSlotBody(b []byte, release func()) *slotBody {
	body := &slotBody{Reader: bytes.NewReader(b), release: release}
	runtime.AddCleanup(body, func(release func()) { release() }, release)
	return body
}

func (b *slotBody) Close() error {
	b.release()
	return nil
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
