package routeguard

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Route is what the guard knows about one route's body.
type Route struct {
	// MaxBody caps the body, in bytes.
	MaxBody int64
	// Expansion is the heap, in bytes, that each body byte costs the route
	// at its worst, measured (see budget.go).
	Expansion int64
	// Allowance is heap, in bytes, the route reserves whatever its body,
	// for work its body's length does not predict.
	Allowance int64
	// BEEF marks a route whose body is a BEEF: its reservation adds what
	// go-sdk's parse of a dense BEEF (parseHeadroom) and the verification of
	// its scripts (scriptHeadroom) may cost beyond Expansion.
	BEEF bool
	// ReadTimeout is how long the body may take to arrive.
	ReadTimeout time.Duration
}

// Reservation is the heap a body of n bytes reserves on route r, and the part
// of it that is scriptHeadroom.
func (r Route) Reservation(n int64) (total, headroom int64) {
	total = r.Allowance + r.Expansion*n
	if r.BEEF {
		headroom = scriptHeadroom(n)
		total += parseHeadroom(n) + headroom
	}
	return total, headroom
}

// ErrReadTimeout means the body did not arrive within the route's read
// timeout. The route answers 408.
var ErrReadTimeout = errors.New("request body not received in time")

// ReadBody reads r's body for route under the ticket. Before reading any byte
// it reserves route's whole reservation for the declared length, or for
// MaxBody when the request declares none, and takes the big-body slot for a
// body that may pass BigBody; once the body is in it returns what a shorter
// undeclared body does not need. It sets the connection's read deadline to
// the route's ReadTimeout and clears it once the body is in, so the server's
// own timeouts govern the rest of the exchange.
//
// Errors: ErrBusy (503) when the heap or the big-body slot is not free in
// time; ErrReadTimeout (408) when the deadline passes; an *http.MaxBytesError
// (400, as before) for a body over MaxBody; any other read error as it came
// (400).
func (t *Ticket) ReadBody(w http.ResponseWriter, r *http.Request, route Route) ([]byte, error) {
	if r.ContentLength > route.MaxBody {
		return nil, &http.MaxBytesError{Limit: route.MaxBody}
	}
	rc := http.NewResponseController(w)
	// ErrNotSupported (a writer with no connection, as in httptest) leaves the
	// server's own timeouts in charge.
	_ = rc.SetReadDeadline(time.Now().Add(route.ReadTimeout))
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()
	declared := r.ContentLength >= 0
	n := route.MaxBody
	if declared {
		n = r.ContentLength
	}
	if n > BigBody {
		if err := t.take(r.Context(), slotBig); err != nil {
			return nil, err
		}
	}
	total, headroom := route.Reservation(n)
	if err := t.Reserve(r.Context(), total); err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.headroom = headroom
	t.mu.Unlock()
	body := http.MaxBytesReader(w, r.Body, route.MaxBody)
	var buf []byte
	var err error
	if declared {
		buf = make([]byte, n)
		_, err = io.ReadFull(body, buf)
	} else {
		buf, err = io.ReadAll(body)
	}
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, ErrReadTimeout
		}
		return nil, err
	}
	if !declared {
		need, h := route.Reservation(int64(len(buf)))
		t.Unreserve(total - need)
		t.mu.Lock()
		t.headroom = h
		t.mu.Unlock()
		if int64(len(buf)) <= BigBody {
			t.leave(slotBig)
		}
	}
	return buf, nil
}

// BodyStatus maps a ReadBody error to the route's status and message. A
// MaxBytesError and any other read error keep the 400 the routes answered
// before the guard; prefix is the route's own wording for those.
func BodyStatus(err error, prefix string) (int, string) {
	switch {
	case errors.Is(err, ErrBusy):
		return http.StatusServiceUnavailable, err.Error()
	case errors.Is(err, ErrReadTimeout):
		return http.StatusRequestTimeout, err.Error()
	default:
		return http.StatusBadRequest, fmt.Sprintf("%s%v", prefix, err)
	}
}
