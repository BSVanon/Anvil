package routeguard

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

// ErrBodyTooSlow means the body did not start within bodyread.ReadGrace, or
// fell below bodyread.MinReadRate on average after it. It wraps
// ErrReadTimeout, so the route answers 408.
var ErrBodyTooSlow = fmt.Errorf("%w: a body must start within %v and then arrive at %d bytes a second or more",
	ErrReadTimeout, bodyread.ReadGrace, bodyread.MinReadRate)

// pacer reads a request body under the connection's read deadline, which it
// sets before each read: by grace + n/minRate after start, more than n bytes
// must have arrived, and all of the body by end. These are bodyread's limits
// for the replies this node reads, applied to the requests it serves.
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

// newPacer starts pacing body, which the guard g reads for w's request, now,
// with timeout for all of it.
func newPacer(g *Guard, w http.ResponseWriter, body io.Reader, timeout time.Duration) *pacer {
	start := time.Now()
	return &pacer{
		r:       body,
		rc:      http.NewResponseController(w),
		start:   start,
		end:     start.Add(timeout),
		grace:   g.grace,
		minRate: g.minRate,
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
