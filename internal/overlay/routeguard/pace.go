package routeguard

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

// MinBodyRate is the least average rate, in bytes a second, at which a
// request body of up to BigBody bytes must arrive once bodyread.ReadGrace has
// passed. It is half bodyread.MinReadRate, the rate this node asks of the
// replies it reads, so that a body of 1 MB sent at 200 kbit/s (25,000 bytes a
// second), which that rate cut off after 8.4 s (cold review round 4 RISK 6),
// is read in 40 s, within the 63 s its length allows (TestPacing_RealTime).
const MinBodyRate int64 = 16 << 10

// BigBodyRate is the least average rate for a body over BigBody:
// bodyread.MinReadRate, the floor every body had before MinBodyRate. Such a
// body holds the one big-body slot, which every other body over BigBody
// waits for, so the lower floor must not make that slot cheaper to hold.
// Holds of smaller bodies are many at once and capped per client.
const BigBodyRate int64 = bodyread.MinReadRate

// ErrBodyTooSlow means the body did not start within bodyread.ReadGrace, or
// fell below its pace after it (Route.MinRate). It wraps ErrReadTimeout, so
// the route answers 408.
var ErrBodyTooSlow = fmt.Errorf("%w: a body must start within %v and then arrive at %d bytes a second or more (%d over %d bytes), "+
	"or faster when it is too long to arrive within the route's read timeout at that rate",
	ErrReadTimeout, bodyread.ReadGrace, MinBodyRate, BigBodyRate, BigBody)

// MinRate is the average rate, in bytes a second, at which a body of n bytes
// must arrive on route r once bodyread.ReadGrace has passed: MinBodyRate, or
// BigBodyRate when n is over BigBody, or the rate that brings all n bytes in
// by the route's ReadTimeout when that is faster. A body that declares no
// length is paced as one of MaxBody bytes, as it is reserved.
func (r Route) MinRate(n int64) int64 {
	return paceRate(n, r.ReadTimeout, bodyread.ReadGrace, MinBodyRate)
}

// paceRate is the average rate, in bytes a second, at which a body of n bytes
// must arrive once grace has passed on a route whose bodies must arrive
// within timeout: floor, raised as BigBodyRate is over MinBodyRate when n is
// over BigBody, or n over the time from grace to timeout when that is faster.
// Without that last term a body could be sent at the floor for as long as
// timeout allows, and hold the reservation of all n bytes while it sent a
// fraction of them.
func paceRate(n int64, timeout, grace time.Duration, floor int64) int64 {
	if n > BigBody {
		floor = floor * BigBodyRate / MinBodyRate
	}
	span := timeout - grace
	if span <= 0 || n <= 0 {
		return floor
	}
	return max(floor, int64(math.Ceil(float64(n)/span.Seconds())))
}

// pacer reads a request body under the connection's read deadline, which it
// sets before each read: by grace + n/minRate after start, more than n bytes
// must have arrived, and all of the body by end.
type pacer struct {
	r       io.Reader
	rc      *http.ResponseController // nil once the writer has refused a deadline
	start   time.Time                // when the read began, moved on by the guard's own waits
	end     time.Time                // when the route's ReadTimeout passes, never moved
	grace   time.Duration
	minRate int64
	have    int64     // bytes read so far
	set     time.Time // the deadline the last read ran under, zero when none was set
	eof     bool      // the body has ended
}

// newPacer starts pacing body, n bytes long, which the guard g reads for w's
// request, now, with timeout for all of it: after g's grace it must arrive at
// g's rate, or at the rate that brings n bytes in by timeout when that is
// faster.
func newPacer(g *Guard, w http.ResponseWriter, body io.Reader, n int64, timeout time.Duration) *pacer {
	start := time.Now()
	return &pacer{
		r:       body,
		rc:      http.NewResponseController(w),
		start:   start,
		end:     start.Add(timeout),
		grace:   g.grace,
		minRate: paceRate(n, timeout, g.grace, g.minRate),
	}
}

// due is when more than p.have bytes must have arrived.
func (p *pacer) due() time.Time {
	due := p.start.Add(p.grace + time.Duration(p.have)*time.Second/time.Duration(p.minRate))
	if due.After(p.end) {
		return p.end
	}
	return due
}

// Read reads from the body under the deadline for its next byte. A read the
// deadline cuts short fails with ErrBodyTooSlow, or with ErrReadTimeout when
// the deadline was the route's ReadTimeout or the server's own. Once the body
// has ended it sets no deadline: the server is then reading the connection
// itself, to see the client go away, and a deadline would end that read.
func (p *pacer) Read(b []byte) (int, error) {
	if p.eof {
		return 0, io.EOF
	}
	if p.rc != nil {
		due := p.due()
		if err := p.rc.SetReadDeadline(due); err != nil {
			// ErrNotSupported (a writer with no connection, as in httptest)
			// leaves the server's own timeouts in charge.
			p.rc, p.set = nil, time.Time{}
		} else {
			p.set = due
		}
	}
	n, err := p.r.Read(b)
	p.have += int64(n)
	switch {
	case err == io.EOF:
		p.eof = true
	case err != nil && errors.Is(err, os.ErrDeadlineExceeded):
		if !p.set.IsZero() && p.set.Before(p.end) {
			return n, ErrBodyTooSlow
		}
		return n, ErrReadTimeout
	}
	return n, err
}

// pause moves the rate's clock on by d: time the guard spent waiting for its
// own slots and heap, not reading, does not count against the sender. The
// route's ReadTimeout still counts it, as it always has.
func (p *pacer) pause(d time.Duration) { p.start = p.start.Add(d) }

// finish clears the connection's read deadline, so the server's own
// timeouts govern the rest of the exchange.
func (p *pacer) finish() {
	if p.rc != nil {
		_ = p.rc.SetReadDeadline(time.Time{})
	}
}

// expire sets the connection's read deadline in the past, so any read of the
// rest of the body fails at once. A body that has ended has no rest, and the
// server's own read of the connection is not to be ended.
func (p *pacer) expire() {
	if p.rc != nil && !p.eof {
		_ = p.rc.SetReadDeadline(time.Unix(1, 0))
	}
}
