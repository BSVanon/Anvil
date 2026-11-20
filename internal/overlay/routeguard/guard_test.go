package routeguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

const testWait = 100 * time.Millisecond

// TestTicket_ReservationsShareTheBudget: what one ticket holds another cannot
// reserve until it is returned; a wait that runs out is ErrBusy, at about the
// guard's Wait; Close returns everything, once.
func TestTicket_ReservationsShareTheBudget(t *testing.T) {
	g := New(1000, 1, 2, testWait)
	a, _ := g.Begin(false)
	if err := a.Reserve(context.Background(), 600); err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	b, _ := g.Begin(false)
	start := time.Now()
	if err := b.Reserve(context.Background(), 600); !errors.Is(err, ErrBusy) {
		t.Fatalf("second reservation over the budget: %v, want ErrBusy", err)
	}
	if waited := time.Since(start); waited < testWait || waited > testWait+time.Second {
		t.Fatalf("ErrBusy after %v, want about %v", waited, testWait)
	}
	a.Unreserve(100)
	if got := a.Reserved(); got != 500 {
		t.Fatalf("after returning 100 the ticket holds %d, want 500", got)
	}
	a.Close()
	a.Close()
	if err := b.Reserve(context.Background(), 1000); err != nil {
		t.Fatalf("the whole budget after Close: %v", err)
	}
	b.Close()
}

// TestTicket_MoreThanTheBudgetFailsAtOnce: a reservation no wait could
// satisfy is refused without waiting.
func TestTicket_MoreThanTheBudgetFailsAtOnce(t *testing.T) {
	g := New(1000, 1, 1, time.Minute)
	tk, _ := g.Begin(false)
	defer tk.Close()
	start := time.Now()
	if err := tk.Reserve(context.Background(), 1001); !errors.Is(err, ErrBusy) {
		t.Fatalf("reservation over the whole budget: %v, want ErrBusy", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("refused after %v, want at once", waited)
	}
}

// TestTicket_ContextEndsTheWait: a caller whose context ends while it waits
// gets the context's error, not ErrBusy, and holds nothing.
func TestTicket_ContextEndsTheWait(t *testing.T) {
	g := New(10, 1, 1, time.Minute)
	a, _ := g.Begin(false)
	_ = a.Reserve(context.Background(), 10)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	b, _ := g.Begin(false)
	if err := b.Reserve(ctx, 5); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reserve under an ending context: %v", err)
	}
	if b.Reserved() != 0 {
		t.Fatalf("a failed reservation left %d bytes held", b.Reserved())
	}
	a.Close()
	b.Close()
}

// readSmallBody reads a two-byte body through tk's ReadBody, as a route's
// handler does, with no connection behind it, from the loopback address, so
// that only the guard's own limits count it (clients_test.go tests a
// client's).
func readSmallBody(tk *Ticket) error {
	r := httptest.NewRequest(http.MethodPost, "/lookup", strings.NewReader(`{}`))
	r.RemoteAddr = "127.0.0.1:1234"
	_, err := tk.ReadBody(httptest.NewRecorder(), r, Route{MaxBody: 1 << 10, Expansion: 1, ReadTimeout: time.Second})
	return err
}

// TestBegin_ReadPermitsRefuseAtOnce: every ticket begins with a read permit,
// JSON route or not; once every permit is out, one more Begin is ErrBusy
// without waiting. ReadBody returns its ticket's permit once the body is in,
// and Close returns the permit of a ticket that never read one.
func TestBegin_ReadPermitsRefuseAtOnce(t *testing.T) {
	g := New(1000, 1, 2, time.Minute)
	g.read = semaphore.NewWeighted(2)
	a, err := g.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for _, jsonRoute := range []bool{true, false} {
		if _, err := g.Begin(jsonRoute); !errors.Is(err, ErrBusy) {
			t.Fatalf("a third ticket of 2 read permits (JSON route %v): %v, want ErrBusy", jsonRoute, err)
		}
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("refused after %v, want at once", waited)
	}
	if err := readSmallBody(b); err != nil {
		t.Fatal(err)
	}
	c, err := g.Begin(false)
	if err != nil {
		t.Fatalf("a ticket whose body is in still holds its read permit: %v", err)
	}
	a.Close()
	if _, err := g.Begin(true); err != nil {
		t.Fatalf("after Close: %v", err)
	}
	b.Close()
	c.Close()
}

// TestReadBody_TakesAJSONSlotOnceTheBodyIsIn: a JSON route's ticket takes no
// JSON slot when it begins, so requests still waiting for their bodies hold
// none; it takes one without waiting once its body is in and holds it until
// it closes. With every slot taken, the next JSON body is refused with
// ErrBusy at once after it is read, and a BEEF route's ticket takes no slot.
func TestReadBody_TakesAJSONSlotOnceTheBodyIsIn(t *testing.T) {
	g := New(1000, 1, 2, time.Minute)
	var tickets []*Ticket
	for i := range 3 {
		tk, err := g.Begin(true)
		if err != nil {
			t.Fatalf("JSON ticket %d of 3 with 2 JSON slots: %v", i, err)
		}
		tickets = append(tickets, tk)
	}
	for _, tk := range tickets[:2] {
		if err := readSmallBody(tk); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := readSmallBody(tickets[2]); !errors.Is(err, ErrBusy) {
		t.Fatalf("a third JSON body with both slots taken: %v, want ErrBusy", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("refused after %v, want at once", waited)
	}
	beef, _ := g.Begin(false)
	if err := readSmallBody(beef); err != nil {
		t.Fatalf("a BEEF ticket with every JSON slot taken: %v", err)
	}
	tickets[0].Close()
	again, _ := g.Begin(true)
	if err := readSmallBody(again); err != nil {
		t.Fatalf("a JSON body once a slot was returned: %v", err)
	}
	for _, tk := range append(tickets, beef, again) {
		tk.Close()
	}
}

// TestTicket_CPUSlots: a ticket holds at most one CPU slot; another ticket
// waits for it and gets ErrBusy at the guard's Wait; LeaveCPU and Close
// return it.
func TestTicket_CPUSlots(t *testing.T) {
	g := New(1000, 1, 1, testWait)
	a, _ := g.Begin(false)
	if err := a.EnterCPU(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.EnterCPU(context.Background()); err != nil {
		t.Fatalf("a second EnterCPU on the same ticket: %v", err)
	}
	b, _ := g.Begin(false)
	if err := b.EnterCPU(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("EnterCPU with the only slot taken: %v, want ErrBusy", err)
	}
	a.LeaveCPU()
	a.LeaveCPU()
	if err := b.EnterCPU(context.Background()); err != nil {
		t.Fatalf("EnterCPU after LeaveCPU: %v", err)
	}
	b.Close()
	if err := a.EnterCPU(context.Background()); err != nil {
		t.Fatalf("EnterCPU after the holder closed: %v", err)
	}
	a.Close()
}
