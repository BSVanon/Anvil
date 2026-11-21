package ordtrack

import (
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestAPendingTipIsServedAndMarkedMinedLater(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	v2 := h.move(v1, 0, h.inscribed("v2"))
	h.observe(v1)
	h.observe(v2)
	h.wantLatest(origin, op(v2, 0), true)

	// Mined status comes from the tx-status path; the newest mined link
	// marks every link before it mined.
	h.chain.Mine(v1, v2)
	h.tr.checkPending(h.ctx)
	h.wantLatest(origin, op(v2, 0), false)
	if _, pending := h.version(origin, 1); pending {
		t.Fatal("version 1 still pending after a later link mined")
	}
	if h.stat("ordtrack_pending") != 0 || h.stat("ordtrack_rollbacks") != 0 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
}

func TestAMinedSpendMarksTheLinksBeforeItMined(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.observe(v1)
	v2 := h.move(v1, 0, h.inscribed("v2"))
	h.chain.Mine(v1, v2)
	h.observe(v2)
	h.wantLatest(origin, op(v2, 0), false)
	if _, pending := h.version(origin, 1); pending || h.stat("ordtrack_pending") != 0 {
		t.Fatalf("version 1 pending %v, stats %v", pending, h.tr.Stats())
	}
}

func TestAnUnminedTipIsRolledBackAfterTheTimeout(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	// The spend watch caches an unspent answer; keep the origin's checks
	// from leaving one, so the follow below asks again.
	h.woc.set(origin, "down")
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.observe(v1)

	h.clock.advance(DefaultPendingTimeout - time.Minute)
	h.tr.checkPending(h.ctx)
	h.wantLatest(origin, op(v1, 0), true)

	h.clock.advance(2 * pendingCheckEvery)
	h.tr.checkPending(h.ctx)
	h.wantTip(origin, origin)
	h.wantLatest(origin, origin, false)
	if h.stat("ordtrack_rollbacks") != 1 || h.stat("ordtrack_pending") != 0 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
	if got := h.tr.History(origin); len(got) != 1 {
		t.Fatalf("history after rollback = %v", got)
	}

	// The rolled-back spend is not taken again while it stays unmined,
	// whichever source reports it.
	h.observe(v1)
	h.woc.set(origin, v1.TxID().String())
	h.tr.follow(h.ctx, origin)
	h.wantTip(origin, origin)
	// Once mined it is a valid spend like any other.
	h.chain.Mine(v1)
	h.observe(v1)
	h.wantLatest(origin, op(v1, 0), false)
}

func TestAConflictingMinedSpendRollsBack(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	// The spend watch caches an unspent answer; keep the origin's first
	// check from leaving one.
	h.woc.set(origin, "down")
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.observe(v1)
	h.wantLatest(origin, op(v1, 0), true)

	// A different spend of the origin is mined.
	rival := h.move(o, 0, plain())
	h.chain.Mine(rival)
	h.woc.set(origin, rival.TxID().String())
	h.tr.checkPending(h.ctx)

	// Rolled back, then followed again from the origin to the mined spend.
	h.wantTip(origin, op(rival, 0))
	h.wantLatest(origin, origin, false)
	if h.stat("ordtrack_rollbacks") != 1 || h.stat("ordtrack_pending") != 0 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
}

func TestARollbackCascadesThroughLaterLinks(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.chain.Mine(v1)
	h.observe(v1)
	v2 := h.move(v1, 0, h.inscribed("v2"))
	moved := h.move(v2, 0, plain())
	v3 := h.move(moved, 0, h.inscribed("v3"))
	for _, tx := range []*transaction.Transaction{v2, moved, v3} {
		h.observe(tx)
	}
	h.wantLatest(origin, op(v3, 0), true)
	if h.stat("ordtrack_pending") != 3 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}

	h.clock.advance(DefaultPendingTimeout)
	h.tr.checkPending(h.ctx)
	// Back to the last mined link, which is the last mined version.
	h.wantTip(origin, op(v1, 0))
	h.wantLatest(origin, op(v1, 0), false)
	if got := h.tr.History(origin); len(got) != 2 {
		t.Fatalf("history after rollback = %v", got)
	}
	if h.stat("ordtrack_rollbacks") != 1 || h.stat("ordtrack_pending") != 0 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
	for _, tx := range []*transaction.Transaction{v2, moved, v3} {
		h.tr.mu.Lock()
		rolled := h.tr.wasRolledBackLocked(tx.TxID().String())
		h.tr.mu.Unlock()
		if !rolled {
			t.Fatalf("%s not remembered as rolled back", tx.TxID())
		}
	}
}

func TestUnminedLinksAreCapped(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	prev := o
	for i := 0; i < maxPendingLinks; i++ {
		next := h.move(prev, 0, plain())
		h.observe(next)
		prev = next
	}
	h.wantTip(origin, op(prev, 0))
	over := h.move(prev, 0, plain())
	h.observe(over)
	h.wantTip(origin, op(prev, 0))
	if h.stat("ordtrack_pending") != maxPendingLinks {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
	// Once mined, the next spend is a mined link and is taken.
	h.chain.Mine(over)
	h.observe(over)
	h.wantTip(origin, op(over, 0))
}
