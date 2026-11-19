package routeguard

import (
	"context"
	"errors"
	"testing"
	"time"
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

// TestBegin_JSONSlotsRefuseAtOnce: once JSONSlots tickets are open, one more
// is ErrBusy without waiting; closing one frees its slot.
func TestBegin_JSONSlotsRefuseAtOnce(t *testing.T) {
	g := New(1000, 1, 2, time.Minute)
	a, err := g.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Begin(true); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := g.Begin(true); !errors.Is(err, ErrBusy) {
		t.Fatalf("third JSON ticket of 2: %v, want ErrBusy", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("refused after %v, want at once", waited)
	}
	if _, err := g.Begin(false); err != nil {
		t.Fatalf("a BEEF ticket takes no JSON slot: %v", err)
	}
	a.Close()
	if _, err := g.Begin(true); err != nil {
		t.Fatalf("after Close: %v", err)
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
