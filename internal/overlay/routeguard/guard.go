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
//   - Connection time. The body must start within bodyread.ReadGrace, the
//     grace bodyread gives the replies this node reads, then arrive at
//     MinBodyRate on average (BigBodyRate over BigBody), or at the rate that
//     brings it all in within its route's ReadTimeout when that is faster
//     (Route.MinRate), and all of it within that timeout. The connection's
//     read deadline, set through http.ResponseController and moved forward
//     as bytes arrive, enforces them, and is cleared once the body is in, so
//     the node's other routes, the SSE streams among them, keep the server's
//     own timeouts. A body cut short is answered 408.
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
// No one client may hold more than its share of these. A client is the key
// internal/clientkey gives the address the API's rate limits count a request
// under, with the trust_proxy settings Guard.TrustProxy passes on: one IPv4
// address, or one IPv6 /64. A client holds at most ClientReadPermits read
// permits, ClientJSONSlots JSON slots, ClientCPUSlots CPU slots (fewer on a
// small guard), the big-body slot and the execution slot, and a third of the
// heap pool or one reservation larger than that. It takes each from a
// semaphore of its own before the guard's, within one Wait, and returns the
// guard's first: its requests beyond its share wait among themselves rather
// than ahead of other clients' in the guard's queues, and a share used up
// refuses only its own client. A request from a loopback, private or shared
// address (clientkey.Shared), through a proxy that does not name its client
// or one the node does not trust, may stand for many clients; only the
// guard's own limits count it, and the guard logs the first such address,
// and the first public one whose proxy headers it does not use.
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
	// bounds that part: the node sets one at startup, 70% of the memory it
	// may use, unless GOMEMLIMIT is set (cmd/anvil, configureAdmission).
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
	// takes 256 / 2 s = 128 new connections each second, from 32 clients or
	// more (ClientReadPermits).
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

	clients *clientSet

	// The pace a body must keep: bodyread.ReadGrace and MinBodyRate (bytes a
	// second, raised for a body over BigBody), which the package's tests
	// change.
	grace   time.Duration
	minRate int64
}

// New returns a Guard with its own budgets: pool bytes of heap that requests
// may hold reserved at once, beside the execution slot's ExecAllowance, the
// given slot counts and ReadPermits read permits, and each client's share of
// them. Production code shares Default; tests use New for budgets of their
// own.
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
		clients: newClientSet(pool, cpuSlots, jsonSlots),
		grace:   bodyread.ReadGrace,
		minRate: MinBodyRate,
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

	// The client ReadBody bound the ticket to, nil when none; which of the
	// held slots hold the client's too; and what mem holds of its share.
	cl    *client
	own   [5]bool
	clMem int64
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

// Reserve adds n bytes to the ticket's heap reservation, and what that adds
// to the ticket's hold on its client's share, waiting at most the guard's
// Wait, and no longer than ctx allows. It fails with ErrBusy when the bytes
// are not free in time, or at once when the ticket would hold more than the
// whole pool, and with ctx's error when ctx ends first.
func (t *Ticket) Reserve(ctx context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	t.mu.Lock()
	over := t.closed || t.mem+n > t.g.pool
	var own *semaphore.Weighted
	var share int64
	if t.cl != nil {
		own, share = t.cl.mem, min(t.mem+n, t.cl.cap)-t.clMem
	}
	t.mu.Unlock()
	if over {
		return ErrBusy
	}
	if err := acquireBoth(ctx, own, share, t.g.mem, n, t.g.wait); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		release(t.g.mem, n, own, share)
		return ErrBusy
	}
	t.mem += n
	if own != nil {
		t.clMem += max(share, 0)
		t.settle()
	}
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
	t.settle()
}

// Reserved reports the bytes the ticket holds reserved.
func (t *Ticket) Reserved() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mem
}

// Close returns everything the ticket holds, the guard's before its
// client's.
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
	t.settle()
	for i := range t.held {
		t.drop(i)
	}
	t.unbind()
}

// SetRetryAfter stamps the Retry-After header a 503 from the guard carries.
func SetRetryAfter(w http.ResponseWriter) {
	w.Header().Set("Retry-After", strconv.Itoa(RetryAfterSeconds))
}
