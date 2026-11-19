package netguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

// SubmitTimeout bounds one outbound POST to a /submit endpoint, redirects
// included, from sending the request to reading the last byte of the reply.
// go-sdk's broadcast facilitator gives each host 30 s (topic/facilitator.go
// MAX_SHIP_QUERY_TIMEOUT) on a context of its own, so the caller's context
// never shortens it. go-overlay-services starts those sends once the submit's
// SHIP lookup has answered, which the 45 s submit cap bounds, so a submit
// that propagates ends within 45 + 15 = 60 s, the time a typical reverse
// proxy waits, where with go-sdk's 30 s it took 75 s. An honest peer answers
// once it has admitted the transaction; one that propagates before answering,
// as Anvil's canonical /submit does, can take longer, and then only its
// acknowledgement is lost: it already holds the transaction.
const SubmitTimeout = 15 * time.Second

// MaxSteakBytes caps the body of a /submit reply. A STEAK lists, for each
// topic the request named, the indices of admitted outputs and retained or
// removed coins: a few hundred bytes for an ordinary transaction. Indices
// below 100,000 take at most 6 bytes each as JSON, so even a STEAK admitting
// every output of a 100,000-output transaction (at least 900 KB on the wire)
// is about 600 KB.
const MaxSteakBytes int64 = 1 << 20

// steakReadPermits is how many /submit replies are read and decoded at once,
// process-wide. go-sdk sends a transaction to every SHIP host of its topics
// at once, a few to tens today, and a hostile SHIP answer can name thousands.
// Each read holds at most MaxSteakBytes of body and about twice that in the
// JSON decoder's buffer, so 16 reads hold under 48 MiB however many hosts a
// send reaches. An honest STEAK reads in milliseconds and seldom waits.
const steakReadPermits = 16

// steakReads are the permits every /submit reply is read under.
var steakReads = bodyread.NewPermits(steakReadPermits)

// ErrInvalidSteak is returned, from RoundTrip, for a /submit reply that is not
// a STEAK the request could have produced.
var ErrInvalidSteak = errors.New("netguard: rejected STEAK reply")

// exchangeDeadline carries, in the context of a /submit exchange's first
// request, the deadline the whole exchange shares.
type exchangeDeadline struct{}

// roundTripSubmit sends one hop of a /submit exchange under the exchange's
// deadline: SubmitTimeout from its first request, whichever hop this is. A
// 200 reply is read and validated here, under that deadline, and handed on
// as the re-encoded STEAK. Any other reply is handed on capped at
// maxSteakBytes, its exchange ending when it is closed or at the deadline.
// go-sdk's facilitator reads no body but a 200's; the client reads a
// redirect's before the next hop.
func (g *guard) roundTripSubmit(req *http.Request) (*http.Response, error) {
	first := origin(req)
	deadline, ok := first.Context().Value(exchangeDeadline{}).(time.Time)
	if !ok {
		deadline = time.Now().Add(g.exchangeTimeout())
	}
	ctx, cancel := context.WithDeadline(req.Context(), deadline)
	ctx = context.WithValue(ctx, exchangeDeadline{}, deadline)
	resp, err := g.base.RoundTrip(req.WithContext(ctx))
	if err != nil || resp == nil {
		cancel()
		return resp, err
	}
	limit := g.steakCap()
	if resp.ContentLength > limit {
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%w: /submit reply Content-Length %d is over %d bytes", ErrResponseTooLarge, resp.ContentLength, limit)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body = &cancelOnClose{ReadCloser: &cappedBody{rc: resp.Body, left: limit, max: limit}, cancel: cancel}
		return resp, nil
	}
	defer cancel()
	return g.checkSteak(ctx, first, resp, deadline)
}

// checkSteak reads a 200 reply to a /submit under one of the steakReads
// permits, holds it to what the exchange's first request could produce, and
// hands on the STEAK re-encoded. Otherwise the body is closed and RoundTrip
// fails, so go-sdk's facilitator never parses the reply.
func (g *guard) checkSteak(ctx context.Context, first *http.Request, resp *http.Response, deadline time.Time) (*http.Response, error) {
	release, err := steakReads.Acquire(ctx)
	if err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("netguard: /submit reply: %w", err)
	}
	defer release()
	left := time.Until(deadline)
	if left <= 0 {
		_ = resp.Body.Close()
		return nil, g.steakReadError(bodyread.ErrTimeout)
	}
	body, err := bodyread.Read(resp.Body, resp.ContentLength, bodyread.Limits{
		Max: g.steakCap(), Timeout: left, MinRate: g.minRate, Grace: g.grace,
	})
	if err != nil {
		return nil, g.steakReadError(err)
	}
	steak, err := decodeSteak(body, boundsFor(first))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSteak, err)
	}
	out, err := json.Marshal(steak)
	if err != nil {
		return nil, fmt.Errorf("%w: re-encoding: %w", ErrInvalidSteak, err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.TransferEncoding = nil
	return resp, nil
}

func (g *guard) steakReadError(err error) error {
	switch {
	case errors.Is(err, bodyread.ErrTooLarge):
		return fmt.Errorf("%w: /submit reply body is over %d bytes", ErrResponseTooLarge, g.steakCap())
	case errors.Is(err, bodyread.ErrTimeout):
		return fmt.Errorf("netguard: /submit reply not read within the %v exchange timeout", g.exchangeTimeout())
	case errors.Is(err, bodyread.ErrTooSlow):
		return fmt.Errorf("netguard: /submit reply arrived below %d bytes/s after %v", g.minRate, g.grace)
	default:
		return fmt.Errorf("netguard: reading /submit reply: %w", err)
	}
}

func (g *guard) exchangeTimeout() time.Duration {
	if g.submitTimeout <= 0 {
		return SubmitTimeout
	}
	return g.submitTimeout
}

func (g *guard) steakCap() int64 {
	if g.maxSteakBytes <= 0 {
		return MaxSteakBytes
	}
	return g.maxSteakBytes
}

// cancelOnClose ends a /submit exchange's context when its reply body is
// closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
