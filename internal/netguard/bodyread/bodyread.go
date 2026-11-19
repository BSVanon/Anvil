// Package bodyread reads an untrusted response body in full under limits a
// peer cannot stretch: a size cap, a deadline, a minimum rate, and a bounded
// number of reads in progress at once, process-wide.
//
// It depends on nothing else in Anvil, so both netguard, which reads lookup
// replies on http.DefaultClient, and peerhygiene, whose BoundedFacilitator
// may read them on a client of its own, can take their permits from the one
// Lookups pool.
package bodyread

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// LookupPermits is how many lookup replies may be read at once,
	// process-wide. Each holds at most peerhygiene.MaxLookupResponseBytes,
	// 2 MiB, so raw lookup bodies being read, or read and waiting for a
	// decoding slot, hold at most 32 x 2 MiB = 64 MiB. A lookup query
	// reaches tens of hosts (go-sdk's four default SLAP trackers, then the
	// ls_ship hosts they name), each honest reply reads in milliseconds, and
	// a slow host keeps its permit only while it sustains MinReadRate, so 32
	// leaves honest replies a free permit unless 32 hosts at once each send
	// at that rate.
	LookupPermits = 32

	// ReadGrace is how long a body may take before MinReadRate applies to
	// it: a few round trips and TCP slow start, which take well under a
	// second between any two hosts on the internet.
	ReadGrace = 2 * time.Second

	// MinReadRate is the average rate, in bytes per second, a body must keep
	// up after ReadGrace. 32 KiB/s is 256 kbit/s, far below any server's
	// link. The largest honest lookup answers hold tens of advertisements at
	// about 1.15 KiB each, and about 70 during the 2026-06 advertisement
	// flood, some 80 KiB, which this rate allows 2 s + 2.5 s. A 2 MiB body
	// at exactly this rate takes 66 s, so the read's own deadline cuts it
	// first.
	MinReadRate = 32 << 10
)

// Lookups is the process-wide pool of permits that every lookup reply is
// read under.
var Lookups = NewPermits(LookupPermits)

// ErrNoPermit is returned, wrapping the context's cause, when ctx ends while
// Acquire waits for a permit.
var ErrNoPermit = errors.New("bodyread: no read permit came free")

// Permits bounds how many reads are in progress at once.
type Permits struct{ held chan struct{} }

// NewPermits returns a pool of n permits.
func NewPermits(n int) *Permits { return &Permits{held: make(chan struct{}, n)} }

// Acquire waits until a permit is free, or until ctx ends, and takes it. It
// never hands a permit to a context that has ended, so a read whose request
// is already over allocates nothing. release returns the permit the first
// time it is called and does nothing after.
func (p *Permits) Acquire(ctx context.Context) (release func(), err error) {
	select {
	case p.held <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrNoPermit, context.Cause(ctx))
	}
	if ctx.Err() != nil { // both were ready, and select took the permit
		<-p.held
		return nil, fmt.Errorf("%w: %w", ErrNoPermit, context.Cause(ctx))
	}
	var once sync.Once
	return func() { once.Do(func() { <-p.held }) }, nil
}

// InUse is how many permits are taken.
func (p *Permits) InUse() int { return len(p.held) }

// Limits bound one Read.
type Limits struct {
	// Max is the most bytes the body may hold.
	Max int64
	// Timeout bounds the whole read. Zero or less sets no deadline.
	Timeout time.Duration
	// MinRate, when above zero, is the average rate in bytes per second the
	// body must keep up once Grace has passed: by Grace + n/MinRate after
	// the read began, more than n bytes must have arrived.
	MinRate int64
	// Grace is how long the body may take before MinRate applies.
	Grace time.Duration
}

var (
	// ErrTooLarge is returned for a body over Limits.Max, declared or read.
	ErrTooLarge = errors.New("bodyread: body is over its cap")
	// ErrTimeout is returned when the body is not read within
	// Limits.Timeout.
	ErrTimeout = errors.New("bodyread: body not read within its timeout")
	// ErrTooSlow is returned when the body falls below Limits.MinRate.
	ErrTooSlow = errors.New("bodyread: body arrived below the minimum rate")
)

// initialBuffer is the first allocation for a body of unknown length. It
// doubles from there up to Limits.Max+1, so a body of n bytes costs at most
// about 1.5 x n while it grows.
const initialBuffer = 4 << 10

// Read reads body to its end under l and closes it exactly once: from a
// timer, to cut a stalled read short, or else on return. contentLength is
// the declared length, or -1 when unknown. A declared length over l.Max fails
// before anything is read; a known length grows into its declared size the
// same way an unknown one grows into the cap (see readKnown, readUnknown),
// rather than committing one allocation of the full declared length before a
// byte has arrived -- a peer that declares a large Content-Length and sends
// little, or nothing, would otherwise cost this much heap for free.
func Read(body io.ReadCloser, contentLength int64, l Limits) ([]byte, error) {
	r := &reader{body: body, limits: l, start: time.Now()}
	defer r.close()
	if contentLength > l.Max {
		return nil, ErrTooLarge
	}
	if l.Timeout > 0 {
		deadline := time.AfterFunc(l.Timeout, func() { r.cut(ErrTimeout) })
		defer deadline.Stop()
	}
	if l.MinRate > 0 {
		r.slow = time.AfterFunc(r.untilDue(0), func() { r.cut(ErrTooSlow) })
		defer r.slow.Stop()
	}
	if contentLength >= 0 {
		return r.readKnown(contentLength)
	}
	return r.readUnknown()
}

// reader is one Read in progress.
type reader struct {
	body      io.ReadCloser
	limits    Limits
	start     time.Time
	slow      *time.Timer
	closeOnce sync.Once
	reason    atomic.Pointer[error] // why a timer cut the read short
}

func (r *reader) close() { r.closeOnce.Do(func() { _ = r.body.Close() }) }

// cut records why the read is being cut short, the first reason winning,
// and closes the body so a Read blocked on it returns.
func (r *reader) cut(why error) {
	r.reason.CompareAndSwap(nil, &why)
	r.close()
}

// untilDue is how long from now the body has to deliver more than n bytes.
func (r *reader) untilDue(n int64) time.Duration {
	due := r.limits.Grace + time.Duration(n)*time.Second/time.Duration(r.limits.MinRate)
	return due - time.Since(r.start)
}

// got records that the body has delivered n bytes in all.
func (r *reader) got(n int64) {
	if r.slow != nil {
		r.slow.Reset(max(r.untilDue(n), 0))
	}
}

// failed turns a read error into the error Read returns: the reason a timer
// cut the read short, if one did.
func (r *reader) failed(err error) error {
	if why := r.reason.Load(); why != nil {
		return *why
	}
	return err
}

// readKnown reads exactly n bytes, grown from a small initial allocation up
// to n, doubling as bytes arrive (the same growth readUnknown uses, bounded
// above by n instead of by Max+1): a body that declares n but sends less, or
// nothing, before it is cut short never cost more than what it actually
// delivered.
func (r *reader) readKnown(n int64) ([]byte, error) {
	buf := make([]byte, 0, min(n, initialBuffer))
	for have := int64(0); have < n; {
		if int64(len(buf)) == int64(cap(buf)) {
			grown := make([]byte, len(buf), min(2*int64(cap(buf)), n))
			copy(grown, buf)
			buf = grown
		}
		k, err := r.body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+k]
		have = int64(len(buf))
		r.got(have)
		if err == io.EOF && have < n {
			return nil, r.failed(io.ErrUnexpectedEOF)
		}
		if err != nil && err != io.EOF {
			return nil, r.failed(err)
		}
	}
	return buf, nil
}

func (r *reader) readUnknown() ([]byte, error) {
	// One byte past the cap tells reaching it from going over. A full buffer
	// is never at this limit: reading that far has already failed below.
	limit := r.limits.Max + 1
	buf := make([]byte, 0, min(initialBuffer, limit))
	for {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(2*int64(cap(buf)), limit))
			copy(grown, buf)
			buf = grown
		}
		k, err := r.body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+k]
		r.got(int64(len(buf)))
		if int64(len(buf)) > r.limits.Max {
			return nil, ErrTooLarge
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, r.failed(err)
		}
	}
}
