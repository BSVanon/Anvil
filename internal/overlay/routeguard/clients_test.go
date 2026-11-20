package routeguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two clients, by the TEST-NET-3 addresses the guard counts as public.
const clientA, clientB = "203.0.113.1", "203.0.113.2"

// warnings counts the guard's once-only warnings.
type warnings struct{ n atomic.Int32 }

func (w *warnings) warn(string, ...any) { w.n.Add(1) }

// quiet returns g with its warnings counted rather than logged.
func quiet(g *Guard) (*Guard, *warnings) {
	w := &warnings{}
	g.clients.warn = w.warn
	return g, w
}

// requestFrom is a POST with a body of n bytes declared, from remote, with the
// X-Forwarded-For values xff.
func requestFrom(remote string, n int64, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/lookup", nil)
	r.RemoteAddr = net.JoinHostPort(remote, "5555")
	r.ContentLength = n
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

// begin starts a ticket and binds it to r's client, as ReadBody does first.
func begin(t *testing.T, g *Guard, r *http.Request) (*Ticket, error) {
	t.Helper()
	tk, err := g.Begin(false)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := tk.bind(r); err != nil {
		tk.Close()
		return nil, err
	}
	return tk, nil
}

// ticketOf is a ticket of client ip whose body is in: begun, bound to ip, and
// its read permits returned.
func ticketOf(g *Guard, ip string) (*Ticket, error) {
	tk, err := g.Begin(false)
	if err != nil {
		return nil, err
	}
	if err := tk.bind(requestFrom(ip, 10)); err != nil {
		tk.Close()
		return nil, err
	}
	tk.leave(slotRead)
	return tk, nil
}

// beginAs is ticketOf, failing the test when it fails.
func beginAs(t *testing.T, g *Guard, ip string) *Ticket {
	t.Helper()
	tk, err := ticketOf(g, ip)
	if err != nil {
		t.Fatalf("a ticket of %s: %v", ip, err)
	}
	return tk
}

// refsOf is how many tickets and hand-offs refer to client key.
func refsOf(g *Guard, key string) int {
	g.clients.mu.Lock()
	defer g.clients.mu.Unlock()
	if c := g.clients.byKey[key]; c != nil {
		return c.refs
	}
	return 0
}

// TestClient_ReadPermitsArePerClient: one client holds at most
// ClientReadPermits read permits, the next of its requests is refused at once,
// another client still gets one, and a permit its client returns is free
// again for that client (cold review round 4 RISK 3, single source).
func TestClient_ReadPermitsArePerClient(t *testing.T) {
	g, _ := quiet(New(1<<20, 4, 64, time.Minute))
	var held []*Ticket
	for i := range ClientReadPermits {
		tk, err := begin(t, g, requestFrom(clientA, 10))
		if err != nil {
			t.Fatalf("read permit %d of client A: %v", i, err)
		}
		held = append(held, tk)
	}
	start := time.Now()
	if _, err := begin(t, g, requestFrom(clientA, 10)); !errors.Is(err, ErrBusy) {
		t.Fatalf("client A's read permit %d: %v, want ErrBusy", ClientReadPermits+1, err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("refused after %v, want at once", waited)
	}
	b, err := begin(t, g, requestFrom(clientB, 10))
	if err != nil {
		t.Fatalf("client B with client A at its cap: %v", err)
	}
	if n := ReadPermits - countFree(g); n != ClientReadPermits+1 {
		t.Fatalf("%d of the guard's read permits are out, want %d: a refused request kept one", n, ClientReadPermits+1)
	}
	held[0].Close()
	again, err := begin(t, g, requestFrom(clientA, 10))
	if err != nil {
		t.Fatalf("client A once one of its permits was returned: %v", err)
	}
	for _, tk := range append(held, b, again) {
		tk.Close()
	}
	if n := g.clients.size(); n != 0 {
		t.Fatalf("%d clients are still kept once every ticket closed", n)
	}
}

// countFree counts g's free read permits.
func countFree(g *Guard) int {
	n := 0
	for g.read.TryAcquire(1) {
		n++
	}
	g.read.Release(int64(n))
	return n
}

// TestClient_MemoryShare: one client holds reserved at most its share, a
// third of the pool, across its tickets, or one reservation larger than the
// share; the rest of the pool stays free for other clients, and what the
// client returns, by Unreserve or Close, it may reserve again.
func TestClient_MemoryShare(t *testing.T) {
	const pool, share = 3000, 1000
	g, _ := quiet(New(pool, 4, 64, testWait))
	a1, a2, a3 := beginAs(t, g, clientA), beginAs(t, g, clientA), beginAs(t, g, clientA)
	if err := a1.Reserve(t.Context(), 600); err != nil {
		t.Fatal(err)
	}
	if err := a2.Reserve(t.Context(), share-600); err != nil {
		t.Fatalf("client A up to its share: %v", err)
	}
	start := time.Now()
	if err := a3.Reserve(t.Context(), 1); !errors.Is(err, ErrBusy) {
		t.Fatalf("client A past its share, with %d of the pool free: %v, want ErrBusy", pool-share, err)
	}
	if waited := time.Since(start); waited < testWait {
		t.Fatalf("refused after %v, before the guard's Wait", waited)
	}
	b := beginAs(t, g, clientB)
	start = time.Now()
	if err := b.Reserve(t.Context(), share); err != nil || time.Since(start) > testWait/2 {
		t.Fatalf("client B, its share, with client A at its own: %v after %v, want at once", err, time.Since(start))
	}
	a1.Unreserve(500)
	if err := a3.Reserve(t.Context(), 500); err != nil {
		t.Fatalf("client A, the 500 bytes of its share a1 returned: %v", err)
	}
	for _, tk := range []*Ticket{a1, a2, a3, b} {
		tk.Close()
	}

	big := beginAs(t, g, clientA)
	if err := big.Reserve(t.Context(), 2*share); err != nil {
		t.Fatalf("client A, one reservation over its share: %v", err)
	}
	other := beginAs(t, g, clientA)
	if err := other.Reserve(t.Context(), 1); !errors.Is(err, ErrBusy) {
		t.Fatalf("client A beside its reservation over its share: %v, want ErrBusy", err)
	}
	b = beginAs(t, g, clientB)
	if err := b.Reserve(t.Context(), pool-2*share); err != nil {
		t.Fatalf("client B, the rest of the pool: %v", err)
	}
	b.Close()
	big.Unreserve(3 * share / 2)
	if got := big.Reserved(); got != share/2 {
		t.Fatalf("after Unreserve the ticket holds %d, want %d", got, share/2)
	}
	if err := other.Reserve(t.Context(), share/2); err != nil {
		t.Fatalf("client A, the half of its share Unreserve returned: %v", err)
	}
	other.Close()
	big.Close()
	if n := g.clients.size(); n != 0 {
		t.Fatalf("%d clients are still kept once every ticket closed", n)
	}
	whole := beginAs(t, g, clientA)
	defer whole.Close()
	if err := whole.Reserve(t.Context(), pool); err != nil {
		t.Fatalf("client A, the whole pool, once nothing else is held: %v", err)
	}
}

// TestClient_CPUAndJSONSlotsArePerClient: one client holds at most
// ClientCPUSlots CPU slots, or one fewer than a small guard has, and
// ClientJSONSlots JSON slots; another client gets a slot of each meanwhile.
func TestClient_CPUAndJSONSlotsArePerClient(t *testing.T) {
	for _, c := range []struct {
		cpuSlots int64
		perCPU   int
	}{{8, ClientCPUSlots}, {3, 2}, {2, 1}} {
		g, _ := quiet(New(1<<20, c.cpuSlots, JSONSlots, testWait))
		var held []*Ticket
		for i := range c.perCPU {
			tk := beginAs(t, g, clientA)
			if err := tk.EnterCPU(t.Context()); err != nil {
				t.Fatalf("%d CPU slots: client A's slot %d: %v", c.cpuSlots, i, err)
			}
			held = append(held, tk)
		}
		extra := beginAs(t, g, clientA)
		if err := extra.EnterCPU(t.Context()); !errors.Is(err, ErrBusy) {
			t.Fatalf("%d CPU slots: client A's slot %d: %v, want ErrBusy", c.cpuSlots, c.perCPU+1, err)
		}
		b := beginAs(t, g, clientB)
		if err := b.EnterCPU(t.Context()); err != nil {
			t.Fatalf("%d CPU slots: client B with client A at its cap: %v", c.cpuSlots, err)
		}
		for _, tk := range append(held, extra, b) {
			tk.Close()
		}
	}
	g, _ := quiet(New(1<<20, 4, JSONSlots, testWait))
	var held []*Ticket
	for i := range ClientJSONSlots {
		tk := beginAs(t, g, clientA)
		if err := tk.tryTake(slotJSON); err != nil {
			t.Fatalf("client A's JSON slot %d: %v", i, err)
		}
		held = append(held, tk)
	}
	extra := beginAs(t, g, clientA)
	if err := extra.tryTake(slotJSON); !errors.Is(err, ErrBusy) {
		t.Fatalf("client A's JSON slot %d: %v, want ErrBusy", ClientJSONSlots+1, err)
	}
	b := beginAs(t, g, clientB)
	if err := b.tryTake(slotJSON); err != nil {
		t.Fatalf("client B with client A at its cap: %v", err)
	}
	for _, tk := range append(held, extra, b) {
		tk.Close()
	}
}

// TestClient_OneSlotTakesTurnsAcrossClients (cold review round 3 S3): a
// client that keeps the execution slot busy with submit after submit, eight
// at a time, cannot queue them ahead of another client's: each of the other
// client's submits gets the slot at the next hand-off, within one hold, though
// the eight would take eight holds. So do the big-body slot and a CPU slot on
// a guard with one.
func TestClient_OneSlotTakesTurnsAcrossClients(t *testing.T) {
	const hold = 100 * time.Millisecond
	for name, slot := range map[string]int{"execution slot": slotExec, "the one CPU slot": slotCPU, "big-body slot": slotBig} {
		g, _ := quiet(New(1<<20, 1, JSONSlots, 4*hold))
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					tk, err := ticketOf(g, clientA)
					if err != nil {
						continue
					}
					if tk.take(context.Background(), slot) == nil {
						time.Sleep(hold)
						tk.handOnExec()
					}
					tk.Close()
				}
			}()
		}
		time.Sleep(3 * hold)
		var longest time.Duration
		for i := range 5 {
			tk := beginAs(t, g, clientB)
			start := time.Now()
			err := tk.take(t.Context(), slot)
			waited := time.Since(start)
			tk.handOnExec()
			tk.Close()
			if err != nil {
				t.Errorf("%s: client B's request %d with client A's eight queued: %v after %v", name, i, err, waited)
			}
			longest = max(longest, waited)
		}
		close(stop)
		wg.Wait()
		t.Logf("%s: client A holding it %v at a time, eight requests at once: client B waited at most %v (guard's Wait %v)", name, hold, longest, 4*hold)
		for end := time.Now().Add(5 * time.Second); g.clients.size() != 0; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(end) {
				t.Errorf("%s: %d clients are still kept 5 s after every ticket closed", name, g.clients.size())
				break
			}
		}
	}
}
