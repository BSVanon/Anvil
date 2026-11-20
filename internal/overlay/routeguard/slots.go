package routeguard

import (
	"context"
	"time"

	"golang.org/x/sync/semaphore"
)

// take takes slot i, its client's first and then the guard's, waiting at most
// the guard's Wait for the two together: ErrBusy when they are not free in
// time. A ticket holds each slot at most once. A client's requests beyond its
// own share of the slot wait for the client's semaphore, so at most that
// share of them stand in the guard's queue, which serves its waiters in
// order: another client's request waits for at most that many of the
// client's ahead of it.
func (t *Ticket) take(ctx context.Context, i int) error {
	t.mu.Lock()
	held, closed, own := t.held[i], t.closed, t.ownSlot(i)
	t.mu.Unlock()
	if closed {
		return ErrBusy
	}
	if held {
		return nil
	}
	if err := acquireBoth(ctx, own, 1, t.g.slot(i), 1, t.g.wait); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		release(t.g.slot(i), 1, own, 1)
		return ErrBusy
	}
	t.held[i], t.own[i] = true, own != nil
	return nil
}

// tryTake takes slot i, its client's and the guard's, without waiting:
// ErrBusy when either is not free.
func (t *Ticket) tryTake(i int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.closed:
		return ErrBusy
	case t.held[i]:
		return nil
	}
	own := t.ownSlot(i)
	if own != nil && !own.TryAcquire(1) {
		return ErrBusy
	}
	if !t.g.slot(i).TryAcquire(1) {
		release(nil, 0, own, 1)
		return ErrBusy
	}
	t.held[i], t.own[i] = true, own != nil
	return nil
}

// leave returns slot i, if the ticket holds it.
func (t *Ticket) leave(i int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.drop(i)
}

// drop returns slot i, if the ticket holds it: the guard's first, then the
// client's. Under t.mu.
func (t *Ticket) drop(i int) {
	if !t.held[i] {
		return
	}
	t.held[i] = false
	var own *semaphore.Weighted
	if t.own[i] {
		t.own[i], own = false, t.cl.slot[i]
	}
	release(t.g.slot(i), 1, own, 1)
}

// EnterCPU takes a verification CPU slot: ErrBusy when none is free within
// the guard's Wait.
func (t *Ticket) EnterCPU(ctx context.Context) error { return t.take(ctx, slotCPU) }

// LeaveCPU returns the ticket's CPU slot, if it holds one.
func (t *Ticket) LeaveCPU() { t.leave(slotCPU) }

// acquireBoth takes n from own, a client's semaphore that may be nil, and then
// m from global, waiting at most wait for the two together. A wait that runs
// out is ErrBusy; ctx ending first is ctx's error. On failure it holds
// neither.
func acquireBoth(ctx context.Context, own *semaphore.Weighted, n int64, global *semaphore.Weighted, m int64, wait time.Duration) error {
	by := time.Now().Add(wait)
	if own != nil && n > 0 {
		if err := acquireBy(ctx, own, n, by); err != nil {
			return err
		}
	}
	if err := acquireBy(ctx, global, m, by); err != nil {
		release(nil, 0, own, n)
		return err
	}
	return nil
}

// acquireBy takes n from s by the deadline by. A wait that runs out is
// ErrBusy; ctx ending first is ctx's error.
func acquireBy(ctx context.Context, s *semaphore.Weighted, n int64, by time.Time) error {
	if s.TryAcquire(n) {
		return nil
	}
	wctx, cancel := context.WithDeadline(ctx, by)
	defer cancel()
	if err := s.Acquire(wctx, n); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrBusy
	}
	return nil
}

// release returns m to global and then n to own, either of which may be nil.
func release(global *semaphore.Weighted, m int64, own *semaphore.Weighted, n int64) {
	if global != nil && m > 0 {
		global.Release(m)
	}
	if own != nil && n > 0 {
		own.Release(n)
	}
}
