package routeguard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// ReadBody reads r's body for route under the ticket, in this order:
//
//  1. A declared length over MaxBody fails at once.
//  2. It binds the ticket to r's client, whose read permit it takes beside
//     the guard's one the ticket holds, without waiting.
//  3. It waits for the body's first byte holding nothing but the read
//     permits. The body must start within bodyread.ReadGrace. The first read
//     sends 100 Continue to a client that asked for it, so such a client
//     starts sending before the guard decides steps 4 and 6.
//  4. Once the first byte is in, a body that may pass BigBody takes the
//     big-body slot, and the ticket reserves route's whole reservation for
//     the declared length, or for MaxBody when the request declares none. An
//     empty body takes neither.
//  5. It reads the rest, which must keep up route.MinRate(n) on average for
//     the n bytes step 4 reserved for (by ReadGrace + k/rate after the read
//     began, not counting the guard's own waits in step 4, more than k bytes
//     must have arrived), all of it within the route's ReadTimeout. The
//     connection's read deadline, set through http.ResponseController and
//     moved forward as bytes arrive, enforces both.
//  6. Once the body is in it clears the read deadline, so the server's own
//     timeouts govern the rest of the exchange, returns the read permits and
//     what a shorter undeclared body does not need, and, on a JSON route's
//     ticket, takes a JSON slot without waiting.
//
// Errors: ErrBusy (503) when the client holds all its read permits, when the
// big-body slot or the heap is not free within the guard's Wait, or when no
// JSON slot is free; ErrBodyTooSlow, which wraps ErrReadTimeout (408), when
// the body does not start within ReadGrace or falls below its rate;
// ErrReadTimeout (408) when the route's ReadTimeout passes; an
// *http.MaxBytesError (400, as before) for a body over MaxBody; any other read
// error as it came (400). A body ReadBody stops reading once it has begun, cut
// short or refused the big-body slot or the heap, is abandoned (see abandon),
// and one refused in step 2 is too, unread: its read deadline is left passed,
// and the server answers with Connection: close and closes the connection
// once the client has had time to read the answer.
func (t *Ticket) ReadBody(w http.ResponseWriter, r *http.Request, route Route) ([]byte, error) {
	defer t.leave(slotRead)
	if r.ContentLength > route.MaxBody {
		return nil, &http.MaxBytesError{Limit: route.MaxBody}
	}
	if err := t.bind(r); err != nil {
		refuse(w, r)
		return nil, err
	}
	buf, err := t.read(w, r, route)
	if err != nil {
		return nil, err
	}
	t.leave(slotRead)
	if t.jsonRoute {
		if err := t.tryTake(slotJSON); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// read does steps 3 to 5 of ReadBody and clears the read deadline once the
// body is in.
func (t *Ticket) read(w http.ResponseWriter, r *http.Request, route Route) ([]byte, error) {
	if r.ContentLength == 0 {
		// Nothing to wait for. The server is already reading the connection
		// past this request, and a deadline would end that read.
		return []byte{}, nil
	}
	declared := r.ContentLength >= 0
	n := route.MaxBody
	if declared {
		n = r.ContentLength
	}
	// The pacer takes r.ContentLength directly, not n: a declared length
	// paces the body against its own total, but an undeclared one (-1) has
	// none to pace against, so the pacer paces it against the bytes read so
	// far instead, on the same schedule (cold review round 4 RISK 2). n
	// itself still reserves as if the body were MaxBody, below: an undeclared
	// body's heap cost is capped before its length is known, whatever its
	// pace.
	p := newPacer(t.g, w, http.MaxBytesReader(w, r.Body, route.MaxBody), r.ContentLength, route.ReadTimeout)
	fail := func(err error) ([]byte, error) {
		abandon(w, p)
		return nil, err
	}
	var first [1]byte
	k, err := p.Read(first[:])
	for k == 0 && err == nil {
		k, err = p.Read(first[:])
	}
	switch {
	case k == 0 && err == io.EOF: // an empty chunked body
		p.finish()
		return []byte{}, nil
	case err != nil && err != io.EOF:
		return fail(err)
	}
	waiting := time.Now()
	if n > BigBody {
		if err := t.take(r.Context(), slotBig); err != nil {
			return fail(err)
		}
	}
	total, headroom := route.Reservation(n)
	if err := t.Reserve(r.Context(), total); err != nil {
		return fail(err)
	}
	t.mu.Lock()
	t.headroom = headroom
	t.mu.Unlock()
	p.pause(time.Since(waiting))
	var buf []byte
	if declared {
		buf = make([]byte, n)
		buf[0] = first[0]
		_, err = io.ReadFull(p, buf[1:])
	} else {
		buf, err = io.ReadAll(io.MultiReader(bytes.NewReader(first[:]), p))
	}
	if err != nil {
		return fail(err)
	}
	p.finish()
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

// abandon gives up the rest of a body ReadBody has begun to read. The read
// deadline is left passed, so nothing the server does after the handler, its
// read of what remains of an unread body among it, waits for the client. And
// the server is told, through http.MaxBytesReader, which "tells the
// ResponseWriter to close the connection after the limit has been reached",
// that the body went over its cap: a cap of 0, passed by one byte held in
// memory, not read from the client. net/http then answers with Connection:
// close, half-closes the connection and waits before it closes it, so a
// client still sending, one that was sent 100 Continue among them, gets the
// answer rather than a reset.
func abandon(w http.ResponseWriter, p *pacer) {
	p.expire()
	closeAfter(w)
}

// refuse gives up, unread, the body of r, which ReadBody refused before
// reading any of it, as abandon gives up one it has begun. Until a body has
// been read the server does not read the connection past it, so the deadline
// ends no read of the server's own; a request with no body has nothing to
// give up.
func refuse(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength == 0 {
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Unix(1, 0))
	closeAfter(w)
}

// closeAfter tells the server to close the connection after its answer.
func closeAfter(w http.ResponseWriter) {
	_, _ = http.MaxBytesReader(w, io.NopCloser(bytes.NewReader([]byte{0})), 0).Read(make([]byte, 1))
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
