package netguard

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
)

// checkLookup reads a lookup reply in full, up to maxLookupBytes, under one of
// the process-wide bodyread.Lookups read permits, and only then takes a
// decoding slot, validates the answer and hands it on, as a fresh body of the
// same bytes that keeps the slot until it is closed. go-sdk's facilitator
// closes the body only after decoding the answer, so the slot covers its
// decoding too. A peer that sends its reply slowly therefore holds a read
// permit, of which there are many, and never a decoding slot, of which there
// are few.
//
// The read permit is held until the slot is taken, or the wait for one fails:
// a body read and waiting for its slot is still counted, so raw bodies held
// outside the slots come to at most LookupPermits x maxLookupBytes, and once
// a slot is taken the slot budget counts the body instead.
//
// Whatever stops the reply being handed on returns what it took and closes
// the original body, and RoundTrip fails, so go-sdk's facilitator never
// parses the reply. Failing to get a permit or a slot in time wraps
// peerhygiene.ErrNoLookupSlot, which hygiene does not count against the host.
func (g *guard) checkLookup(req *http.Request, resp *http.Response) (*http.Response, error) {
	ctx := req.Context()
	if resp.ContentLength > g.maxLookupBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: lookup Content-Length %d is over %d bytes", ErrResponseTooLarge, resp.ContentLength, g.maxLookupBytes)
	}
	releaseRead, err := bodyread.Lookups.Acquire(ctx)
	if err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("netguard: %w: %w", peerhygiene.ErrNoLookupSlot, err)
	}
	body, err := g.readLookupBody(resp)
	if err != nil {
		releaseRead()
		return nil, err
	}
	releaseSlot, err := peerhygiene.AcquireLookupSlot(ctx)
	releaseRead()
	if err != nil {
		return nil, fmt.Errorf("netguard: %w", err)
	}
	peerhygiene.MarkLookupSlotHeld(ctx)
	contentType, answer, err := prepareLookupAnswer(resp.Header.Get("Content-Type"), body)
	if err != nil {
		releaseSlot()
		return nil, err
	}
	resp.Body = newSlotBody(answer, releaseSlot)
	resp.ContentLength = int64(len(answer))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("Content-Type", contentType)
	resp.Header.Set("Content-Length", strconv.Itoa(len(answer)))
	resp.TransferEncoding = nil
	return resp, nil
}

// prepareLookupAnswer is the one place an accepted lookup reply's bytes are
// chosen for the caller: it returns the content type and body to hand on, or
// an error that refuses the reply. peerhygiene.PrepareLookupAnswer holds the
// answer to its caps and re-encodes a binary answer as the equivalent JSON
// one, each output with its own BEEF, so go-sdk's facilitator does not merge
// the outputs' proofs (see peerhygiene's budget).
func prepareLookupAnswer(contentType string, body []byte) (string, []byte, error) {
	outType, out, err := peerhygiene.PrepareLookupAnswer(contentType, body)
	if err != nil {
		return "", nil, fmt.Errorf("netguard: rejected lookup answer: %w", err)
	}
	return outType, out, nil
}

// readLookupBody reads resp's whole body, failing once it passes
// maxLookupBytes, once readTimeout has passed, or once it falls below minRate
// after grace, and always closes it, exactly once.
func (g *guard) readLookupBody(resp *http.Response) ([]byte, error) {
	body, err := bodyread.Read(resp.Body, resp.ContentLength, bodyread.Limits{
		Max: g.maxLookupBytes, Timeout: g.readTimeout, MinRate: g.minRate, Grace: g.grace,
	})
	switch {
	case err == nil:
		return body, nil
	case errors.Is(err, bodyread.ErrTooLarge):
		return nil, fmt.Errorf("%w: lookup body is over %d bytes", ErrResponseTooLarge, g.maxLookupBytes)
	case errors.Is(err, bodyread.ErrTimeout):
		return nil, fmt.Errorf("netguard: lookup answer not read within %v", g.readTimeout)
	case errors.Is(err, bodyread.ErrTooSlow):
		return nil, fmt.Errorf("netguard: lookup answer arrived below %d bytes/s after %v", g.minRate, g.grace)
	default:
		return nil, fmt.Errorf("netguard: reading lookup answer: %w", err)
	}
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
