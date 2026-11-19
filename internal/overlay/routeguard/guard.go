// Package routeguard bounds what the overlay routes that need no login can make
// this node spend: heap, verification CPU and connection time.
//
// Every guarded request holds a Ticket from one process-wide Guard and takes
// what it needs in this order:
//
//   - Read permits. Begin takes one of ReadPermits without waiting; when none
//     is free the request is answered 503 at once. Until its body's first byte
//     arrives a request holds nothing else, so connections that send only
//     headers hold no heap, no big-body slot and no JSON slot. The permit is
//     returned once the body is in.
//   - Connection time. The body must start within bodyread.ReadGrace, then
//     keep up bodyread.MinReadRate on average, the limits bodyread applies to
//     the replies this node reads, and arrive within its route's ReadTimeout.
//     The connection's read deadline, set through http.ResponseController and
//     moved forward as bytes arrive, enforces them, and is cleared once the
//     body is in, so the node's other routes, the SSE streams among them, keep
//     the server's own timeouts. A body cut short is answered 408.
//   - Bodies over BigBody. Once the first byte is in, a body that may pass
//     BigBody takes the one big-body slot, so senders of large bodies, slow
//     ones included, cannot take the heap the routes' small requests need.
//   - Heap. Then the request reserves, from a weighted semaphore, all the heap
//     its body may cost: the body's length (the cap, when the length is not
//     declared) times the route's measured expansion, the route's fixed
//     allowance and, for a BEEF, what parsing its scripts may cost (see
//     Route.Reservation). Nothing is reserved later, so a request in flight
//     never queues behind newer ones; what the request turns out not to need
//     is returned as soon as that is known, and the rest when the request
//     ends. A request that cannot reserve within Wait is answered 503 with
//     Retry-After. An empty body reserves nothing: every guarded handler
//     refuses one before any work its route's allowance pays for.
//   - JSON requests. Once its body is in, a JSON-bodied request takes one of
//     JSONSlots without waiting and holds it until it ends; one more is
//     answered 503 at once.
//   - Verification CPU. A submit takes one of CPUSlots slots, max(1,
//     GOMAXPROCS/2), before it verifies, and keeps it until the engine reports
//     the STEAK ready or returns. It waits at most Wait for one, then 503.
//   - Script execution. A submit whose scripts may write new stack elements
//     also takes the one execution slot, which carries ExecAllowance of the
//     budget, and the guard collects garbage before the engine verifies such
//     a submit again and before it hands the slot on.
//
// A client that sends Expect: 100-continue gets its 100 Continue from the
// first read of its body, before the guard decides the big-body slot and the
// reservation. Such a client therefore starts sending before a 503 can refuse
// it; the refusal arrives while its body is in flight, with Connection: close,
// and the server closes the connection once the client has had time to read
// it, as for a body over its cap.
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

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
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

	// JSONSlots caps the JSON-bodied requests in flight at once, counted from
	// when their bodies are in.
	JSONSlots = 64

	// ReadPermits caps the requests reading their bodies at once. One waiting
	// for its first byte holds no reservation, only its connection's buffers,
	// its parsed headers and its goroutine: 13.1 to 14.1 KiB of live heap and
	// 8.1 to 8.6 KiB of stack each, 5.3 to 5.7 MiB for 256, measured in new
	// processes with short headers and both ends of each connection in the
	// process (TestGuard_ReadPermitsBoundIdleConnections in v3engine; repeated
	// in one process, with the server's pooled buffers reused, 2.4 to 2.8 KiB
	// of heap each). It holds its permit for at most bodyread.ReadGrace unless
	// it starts sending, and then it holds a reservation too, which the heap
	// budget bounds. 256 is four times JSONSlots, so JSON requests reach their
	// slots while 192 idle connections are open, and holding every permit
	// takes 256 / 2 s = 128 new connections each second.
	ReadPermits = 256

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
	read *semaphore.Weighted
	wait time.Duration

	// The pace a body must keep: bodyread.ReadGrace and bodyread.MinReadRate
	// (bytes a second), which the package's tests shorten.
	grace   time.Duration
	minRate int64
}

// New returns a Guard with its own budgets: pool bytes of heap that requests
// may hold reserved at once, beside the execution slot's ExecAllowance, the
// given slot counts and ReadPermits read permits. Production code shares
// Default; tests use New for budgets of their own.
func New(pool, cpuSlots, jsonSlots int64, wait time.Duration) *Guard {
	return &Guard{
		mem:     semaphore.NewWeighted(pool),
		pool:    pool,
		big:     semaphore.NewWeighted(1),
		exec:    semaphore.NewWeighted(1),
		cpu:     semaphore.NewWeighted(cpuSlots),
		json:    semaphore.NewWeighted(jsonSlots),
		read:    semaphore.NewWeighted(ReadPermits),
		wait:    wait,
		grace:   bodyread.ReadGrace,
		minRate: bodyread.MinReadRate,
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
	g         *Guard
	mu        sync.Mutex
	mem       int64
	headroom  int64 // of mem: the script parse ReadBody reserved for a BEEF
	held      [5]bool
	jsonRoute bool // ReadBody takes a JSON slot once the body is in
	closed    bool
}

// The slots a ticket may hold, indexing Ticket.held.
const (
	slotJSON = iota
	slotBig
	slotExec
	slotCPU
	slotRead
)

func (g *Guard) slot(i int) *semaphore.Weighted {
	return [...]*semaphore.Weighted{g.json, g.big, g.exec, g.cpu, g.read}[i]
}

// Begin starts a ticket holding one of the guard's read permits, taken
// without waiting: ErrBusy when all ReadPermits are taken. jsonRoute marks a
// JSON route's ticket, whose ReadBody takes a JSON slot once the body is in.
func (g *Guard) Begin(jsonRoute bool) (*Ticket, error) {
	if !g.read.TryAcquire(1) {
		return nil, ErrBusy
	}
	t := &Ticket{g: g, jsonRoute: jsonRoute}
	t.held[slotRead] = true
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

// tryTake takes slot i without waiting: ErrBusy when it is not free.
func (t *Ticket) tryTake(i int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.closed:
		return ErrBusy
	case t.held[i]:
		return nil
	case !t.g.slot(i).TryAcquire(1):
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
