package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/refusallog"
)

// paymentBodyLimits bound one payment-route body read (readPaymentBody): at
// most 1 MiB, the cap these reads always had; after bodyread.ReadGrace (2 s)
// the body must keep up bodyread.MinReadRate (32 KiB/s) on average; and the
// whole read ends by ReadGrace + 1 MiB / MinReadRate (34 s), the time a 1 MiB
// body takes at that rate. A var so tests can shrink it.
var paymentBodyLimits = bodyread.Limits{
	Max:     1 << 20,
	Timeout: bodyread.ReadGrace + (1<<20)*time.Second/bodyread.MinReadRate,
	MinRate: bodyread.MinReadRate,
	Grace:   bodyread.ReadGrace,
}

// paymentBodyPermits is how many payment-route bodies are read at once,
// process-wide, so at most 32 x 1 MiB of them are buffered at a time. A body
// that finds no permit free within paymentBodyLimits.Grace gets 503.
const paymentBodyPermits = 32

// paymentBodyReads is the pool readPaymentBody takes its permits from. A var
// so tests can use a smaller one.
var paymentBodyReads = bodyread.NewPermits(paymentBodyPermits)

// errPaymentBodyDeadline marks a failure to set the connection's read
// deadline, other than a writer that supports none. The body is then not
// read at all, rather than read without its deadline.
var errPaymentBodyDeadline = errors.New("cannot set the request body's read deadline")

// unpacedOnce logs once that payment bodies are read with no connection
// deadline, because the response writer supports none.
var unpacedOnce sync.Once

// paymentBodyError is a failed payment-body read; writePaymentBodyError
// answers it.
type paymentBodyError struct{ err error }

func (e *paymentBodyError) Error() string { return "request body: " + e.err.Error() }
func (e *paymentBodyError) Unwrap() error { return e.err }

// readPaymentBody reads r's body for a payment check under paymentBodyLimits,
// holding a permit from paymentBodyReads, and leaves r.Body reading the same
// bytes again for the handler after the gate. A request with no body takes no
// permit. Errors are *paymentBodyError.
//
// bodyread's own timers cut a slow read by closing the body, but closing a
// server request body does not end a Read blocked on it: net/http's body
// Close waits for the lock that Read holds. So the read also moves the
// connection's read deadline along the same schedule before every Read
// (pacedBody.due), and a stalled body fails at its due time.
func readPaymentBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return []byte{}, nil
	}
	p := &pacedBody{body: r.Body, rc: http.NewResponseController(w), limits: paymentBodyLimits}
	body, err := p.read(r.Context(), r.ContentLength)
	if err != nil {
		p.expire()
		return nil, &paymentBodyError{err}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// readChallengeBody is readPaymentBody for the body a challenge binds, and
// answers a failed read itself; ok is false when it did.
func readChallengeBody(w http.ResponseWriter, r *http.Request) (body []byte, ok bool) {
	body, err := readPaymentBody(w, r)
	if err != nil {
		writePaymentBodyError(w, r, err)
		return nil, false
	}
	return body, true
}

// writePaymentBodyError answers a failed payment-body read with the status
// for its cause, per RFC 9110: 413 Content Too Large (section 15.5.14) for a
// body over the cap; 408 Request Timeout (15.5.9) for one that did not arrive
// at its pace; 503 Service Unavailable (15.6.4) when no read permit came free;
// 500 when the node could not set the deadline; and 400 Bad Request (15.5.1)
// for anything else the client sent, such as a body cut off or badly chunked.
func writePaymentBodyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, bodyread.ErrTooLarge):
		refusallog.Log(r, http.StatusRequestEntityTooLarge, refusallog.ReasonBodyRejected)
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body is over the %d-byte limit for a payment request", paymentBodyLimits.Max))
	case errors.Is(err, bodyread.ErrTooSlow), errors.Is(err, bodyread.ErrTimeout), errors.Is(err, os.ErrDeadlineExceeded):
		refusallog.Log(r, http.StatusRequestTimeout, refusallog.ReasonSlowBody)
		writeError(w, http.StatusRequestTimeout, fmt.Sprintf("request body did not arrive in time: it must start within %v and then average %d bytes a second",
			paymentBodyLimits.Grace, paymentBodyLimits.MinRate))
	case errors.Is(err, bodyread.ErrNoPermit):
		refusallog.Log(r, http.StatusServiceUnavailable, refusallog.ReasonBusy)
		writeUnavailable(w, paymentBodyLimits.Grace, "too many payment request bodies are being read, retry later")
	case errors.Is(err, errPaymentBodyDeadline):
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		refusallog.Log(r, http.StatusBadRequest, refusallog.ReasonBodyRejected)
		writeError(w, http.StatusBadRequest, "request body could not be read: "+err.Error())
	}
}

// pacedBody is a request body read under a connection read deadline that
// follows bodyread's schedule: by Grace + n/MinRate after the read began, more
// than n bytes must have arrived, and all of the body by Timeout.
type pacedBody struct {
	body   io.ReadCloser
	rc     *http.ResponseController // nil once the writer has refused a deadline
	limits bodyread.Limits
	start  time.Time
	have   int64 // bytes read so far
	eof    bool  // the body has ended
}

// read takes a permit, waiting at most Grace for one, and reads the body of
// declared length n (negative when unknown) through bodyread.Read.
func (p *pacedBody) read(ctx context.Context, n int64) ([]byte, error) {
	wait, cancel := context.WithTimeout(ctx, p.limits.Grace)
	release, err := paymentBodyReads.Acquire(wait)
	cancel()
	if err != nil {
		return nil, err
	}
	defer release()
	p.start = time.Now()
	body, err := bodyread.Read(p, n, p.limits)
	if err == nil && !p.eof {
		err = p.setDeadline(time.Time{})
	}
	return body, err
}

// due is when more than p.have bytes must have arrived.
func (p *pacedBody) due() time.Time {
	due := p.start.Add(p.limits.Grace + time.Duration(p.have)*time.Second/time.Duration(p.limits.MinRate))
	if end := p.start.Add(p.limits.Timeout); due.After(end) {
		return end
	}
	return due
}

// Read reads the body under the deadline for its next byte. Once the body has
// ended it clears the deadline: the server then reads the connection itself,
// to see the client go away, and a deadline left set would end that read.
func (p *pacedBody) Read(b []byte) (int, error) {
	if p.eof {
		return 0, io.EOF
	}
	if err := p.setDeadline(p.due()); err != nil {
		return 0, err
	}
	n, err := p.body.Read(b)
	p.have += int64(n)
	if err == io.EOF {
		p.eof = true
		if cerr := p.setDeadline(time.Time{}); cerr != nil {
			return n, cerr
		}
	}
	return n, err
}

func (p *pacedBody) Close() error { return p.body.Close() }

// setDeadline sets the connection's read deadline. A writer that supports
// none (http.ErrNotSupported, as httptest's recorder) leaves the read to
// bodyread's timers, which is logged once; any other failure is returned.
func (p *pacedBody) setDeadline(t time.Time) error {
	if p.rc == nil {
		return nil
	}
	err := p.rc.SetReadDeadline(t)
	if errors.Is(err, http.ErrNotSupported) {
		p.rc = nil
		unpacedOnce.Do(func() {
			slog.Warn("x402: payment request bodies are read with no connection read deadline, because the response writer supports none")
		})
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", errPaymentBodyDeadline, err)
	}
	return nil
}

// expire sets the read deadline in the past after a failed read, so the
// server does not wait on the unread rest of the body when it discards it. The
// request is already refused, so a failure to set it leaves only the server's
// own handling of that rest, and is not reported.
func (p *pacedBody) expire() {
	if p.rc != nil && !p.eof {
		_ = p.rc.SetReadDeadline(time.Unix(1, 0))
	}
}
