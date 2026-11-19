// Package routeguard bounds what the overlay routes that need no login can make
// this node spend: heap, verification CPU and connection time.
//
// Every guarded request holds a Ticket from one process-wide Guard:
//
//   - Heap. Before a request reads its body it reserves, from a weighted
//     semaphore, all the heap its body may cost: the body's length (the cap,
//     when the length is not declared) times the route's measured expansion,
//     the route's fixed allowance and, for a BEEF, what parsing its scripts
//     may cost (see Route.Reservation). Nothing is reserved later, so a
//     request in flight never queues behind newer ones; what the request turns
//     out not to need is returned as soon as that is known, and the rest when
//     the request ends. A request that cannot reserve within Wait is answered
//     503 with Retry-After, before it has sent its body if it asked for 100
//     Continue.
//   - Bodies over BigBody. Only one is in flight at a time, so senders of
//     large bodies, slow ones included, cannot take the heap the routes' small
//     requests need.
//   - Verification CPU. A submit takes one of CPUSlots slots, max(1,
//     GOMAXPROCS/2), before it verifies, and keeps it until the engine reports
//     the STEAK ready or returns. It waits at most Wait for one, then 503.
//   - Script execution. A submit whose scripts may write new stack elements
//     also takes the one execution slot, which carries ExecAllowance of the
//     budget, and the guard collects garbage before the engine verifies such
//     a submit again and before it hands the slot on.
//   - JSON requests. At most JSONSlots JSON-bodied requests are in flight at
//     once; one more is answered 503 at once.
//   - Connection time. A body must arrive within its route's ReadTimeout, set
//     as the connection's read deadline through http.ResponseController and
//     cleared once the body is in, so a slow sender is cut off and the node's
//     other routes, the SSE streams among them, keep the server's own
//     timeouts.
//
// The budgets are constants, not configuration.
package routeguard

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	// MemoryBudget is the heap, in bytes, that guarded requests may hold
	// reserved at once, the execution slot's ExecAllowance included. The
	// reservations cover what the requests hold live. The heap in use also
	// holds garbage the collector has not yet reclaimed, which the budget
	// does not count: at the default GOGC, one submit verifying 50,000
	// instructions had 67 to 77 MiB of heap in use against the 45.8 MiB it
	// reserved, though it held under 10 MiB live. Only a process memory limit
	// (GOMEMLIMIT) bounds that part.
	MemoryBudget int64 = 384 << 20

	// Wait is how long a request waits for heap or a slot before it is
	// answered 503.
	Wait = 2 * time.Second

	// RetryAfterSeconds is the Retry-After a 503 from the guard carries.
	RetryAfterSeconds = 2

	// JSONSlots caps the JSON-bodied requests in flight at once.
	JSONSlots = 64

	// BigBody is the body length past which a request takes the one big-body
	// slot.
	BigBody int64 = 1 << 20

	// BEEFReadTimeout and JSONReadTimeout are how long a request's body may
	// take to arrive.
	BEEFReadTimeout = 120 * time.Second
	JSONReadTimeout = 15 * time.Second
)

// CPUSlots is how many submits may verify at once: half the processors Go
// schedules on, and at least one.
var CPUSlots = int64(max(1, runtime.GOMAXPROCS(0)/2))

// ErrBusy means the guard could not admit the request within Wait. The route
// answers 503 with Retry-After.
var ErrBusy = errors.New("node busy: try again shortly")

// Guard holds the process-wide budgets. The zero value is not usable; use New
// or Default.
type Guard struct {
	mem  *semaphore.Weighted
	pool int64 // mem's size
	big  *semaphore.Weighted
	exec *semaphore.Weighted
	cpu  *semaphore.Weighted
	json *semaphore.Weighted
	wait time.Duration
}

// New returns a Guard with its own budgets: pool bytes of heap that requests
// may hold reserved at once, beside the execution slot's ExecAllowance, and
// the given slot counts. Production code shares Default; tests use New for
// budgets of their own.
func New(pool, cpuSlots, jsonSlots int64, wait time.Duration) *Guard {
	return &Guard{
		mem:  semaphore.NewWeighted(pool),
		pool: pool,
		big:  semaphore.NewWeighted(1),
		exec: semaphore.NewWeighted(1),
		cpu:  semaphore.NewWeighted(cpuSlots),
		json: semaphore.NewWeighted(jsonSlots),
		wait: wait,
	}
}

var defaultGuard = New(MemoryBudget-ExecAllowance, CPUSlots, JSONSlots, Wait)

// Default returns the process-wide Guard that every overlay route shares.
func Default() *Guard { return defaultGuard }

// Or returns g, or Default when g is nil.
func Or(g *Guard) *Guard {
	if g == nil {
		return defaultGuard
	}
	return g
}

// Ticket is one request's hold on a Guard. Its methods are safe for
// concurrent use; Close returns everything it holds and may be called more
// than once.
type Ticket struct {
	g        *Guard
	mu       sync.Mutex
	mem      int64
	headroom int64 // of mem: the script parse ReadBody reserved for a BEEF
	held     [4]bool
	closed   bool
}

// The slots a ticket may hold, indexing Ticket.held.
const (
	slotJSON = iota
	slotBig
	slotExec
	slotCPU
)

func (g *Guard) slot(i int) *semaphore.Weighted {
	return [...]*semaphore.Weighted{g.json, g.big, g.exec, g.cpu}[i]
}

// Begin starts a ticket. A JSON route's ticket takes a JSON slot, without
// waiting: ErrBusy when all JSONSlots are taken.
func (g *Guard) Begin(jsonRoute bool) (*Ticket, error) {
	t := &Ticket{g: g}
	if jsonRoute {
		if !g.json.TryAcquire(1) {
			return nil, ErrBusy
		}
		t.held[slotJSON] = true
	}
	return t, nil
}

// Reserve adds n bytes to the ticket's heap reservation, waiting at most the
// guard's Wait, and no longer than ctx allows. It fails with ErrBusy when the
// bytes are not free in time, or at once when the ticket would hold more than
// the whole pool, and with ctx's error when ctx ends first.
func (t *Ticket) Reserve(ctx context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	t.mu.Lock()
	over := t.closed || t.mem+n > t.g.pool
	t.mu.Unlock()
	if over {
		return ErrBusy
	}
	if err := acquire(ctx, t.g.mem, n, t.g.wait); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		t.g.mem.Release(n)
		return ErrBusy
	}
	t.mem += n
	return nil
}

// Unreserve returns up to n bytes of the ticket's heap reservation.
func (t *Ticket) Unreserve(n int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n = min(n, t.mem)
	if n <= 0 {
		return
	}
	t.mem -= n
	t.headroom = min(t.headroom, t.mem)
	t.g.mem.Release(n)
}

// Reserved reports the bytes the ticket holds reserved.
func (t *Ticket) Reserved() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mem
}

// take takes slot i, waiting at most the guard's Wait: ErrBusy when it is not
// free in time. A ticket holds each slot at most once.
func (t *Ticket) take(ctx context.Context, i int) error {
	t.mu.Lock()
	held, closed := t.held[i], t.closed
	t.mu.Unlock()
	if closed {
		return ErrBusy
	}
	if held {
		return nil
	}
	if err := acquire(ctx, t.g.slot(i), 1, t.g.wait); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		t.g.slot(i).Release(1)
		return ErrBusy
	}
	t.held[i] = true
	return nil
}

// leave returns slot i, if the ticket holds it.
func (t *Ticket) leave(i int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.held[i] {
		t.held[i] = false
		t.g.slot(i).Release(1)
	}
}

// EnterCPU takes a verification CPU slot: ErrBusy when none is free within
// the guard's Wait.
func (t *Ticket) EnterCPU(ctx context.Context) error { return t.take(ctx, slotCPU) }

// LeaveCPU returns the ticket's CPU slot, if it holds one.
func (t *Ticket) LeaveCPU() { t.leave(slotCPU) }

// Close returns everything the ticket holds.
func (t *Ticket) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	if t.mem > 0 {
		t.g.mem.Release(t.mem)
		t.mem, t.headroom = 0, 0
	}
	for i, held := range t.held {
		if held {
			t.held[i] = false
			t.g.slot(i).Release(1)
		}
	}
}

// acquire takes n from s, waiting at most wait. A wait that runs out is
// ErrBusy; ctx ending first is ctx's error.
func acquire(ctx context.Context, s *semaphore.Weighted, n int64, wait time.Duration) error {
	if s.TryAcquire(n) {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if err := s.Acquire(wctx, n); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrBusy
	}
	return nil
}

// SetRetryAfter stamps the Retry-After header a 503 from the guard carries.
func SetRetryAfter(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(RetryAfterSeconds))
}
