package ordtrack

import (
	"errors"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/content"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
)

func TestInscribedTransfersAreVersionsAndPlainOnesOnlyMoveTheTip(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	h.wantTip(origin, origin)
	h.wantLatest(origin, origin, false)

	v1 := h.move(o, 0, h.inscribed("v1"))
	h.observe(v1)
	h.wantTip(origin, op(v1, 0))
	h.wantLatest(origin, op(v1, 0), true)
	if got, pending := h.version(origin, 0); got != origin || pending {
		t.Fatalf("version 0 = %s (pending %v), want the origin", got, pending)
	}

	// An uninscribed transfer moves the tip; the latest version stays.
	moved := h.move(v1, 0, plain())
	h.observe(moved)
	h.wantTip(origin, op(moved, 0))
	h.wantLatest(origin, op(v1, 0), true)
	if _, _, err := h.tr.ResolveVersion(origin, 2); !errors.Is(err, content.ErrNoVersion) {
		t.Fatalf("version 2 before it exists: err %v", err)
	}

	v2 := h.move(moved, 0, h.inscribed("v2"))
	h.observe(v2)
	h.wantLatest(origin, op(v2, 0), true)
	if got, _ := h.version(origin, 2); got != op(v2, 0) {
		t.Fatalf("version 2 = %s, want %s", got, op(v2, 0))
	}
	if got := h.tr.History(origin); len(got) != 3 || got[0] != origin || got[1] != op(v1, 0) || got[2] != op(v2, 0) {
		t.Fatalf("history = %v", got)
	}
	if got, err := h.tr.At(origin, 1); err != nil || got != op(v1, 0) {
		t.Fatalf("At(1) = %s, %v", got, err)
	}
	if n := len(h.envelopes()); n != 3 {
		t.Fatalf("%d tip envelopes published, want one per transfer", n)
	}
	if h.stat("ordtrack_pending") != 3 || h.stat("ordtrack_origins") != 1 {
		t.Fatalf("stats = %v", h.tr.Stats())
	}
}

func TestEndAndBurnCloseTheChain(t *testing.T) {
	h := newHarness(t)
	a, b := h.mint("a"), h.mint("b")
	originA, originB := op(a, 0), op(b, 0)
	h.track(originA, originB)

	v1 := h.move(a, 0, h.inscribed("a1"))
	h.observe(v1)
	// The sat lands in a 5,000-sat output: the chain ends.
	end := h.move(v1, 0, ordtracktest.Out{Sats: 5_000})
	h.observe(end)
	burn := h.burn(b, 0)
	h.observe(burn)

	for _, c := range []struct{ origin, latest, kind string }{
		{originA, op(v1, 0), "end"},
		{originB, originB, "burn"},
	} {
		h.tr.mu.Lock()
		ch := h.tr.chains[c.origin]
		closed, kind := ch.m.Closed, ch.tip.Kind
		h.tr.mu.Unlock()
		if !closed || kind != c.kind {
			t.Fatalf("%s: closed %v, last link %s; want closed by %s", c.origin, closed, kind, c.kind)
		}
		if got := h.latest(c.origin); got != c.latest {
			t.Fatalf("%s: latest %s, want %s", c.origin, got, c.latest)
		}
	}
	if h.tr.Active() || h.watch.Len() != 0 {
		t.Fatalf("closed chains still followed: active %v, watched %d", h.tr.Active(), h.watch.Len())
	}

	// Later spends are ignored.
	later := h.w.Spend(t, []ordtracktest.In{{Tx: end}}, ordtracktest.Out{Sats: 1}, ordtracktest.Out{Sats: 3_000})
	h.store.Add(later)
	h.observe(later)
	if got := h.tr.History(originA); len(got) != 2 {
		t.Fatalf("history after a later spend = %v", got)
	}
	if n := len(h.envelopes()); n != 1 {
		t.Fatalf("%d tip envelopes; only the one transfer is published", n)
	}
}

func TestAnInvalidSpendChangesNothing(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	x := h.moveBy(ordtracktest.NewWallet(t), o, 0, h.inscribed("stolen"))
	h.observe(x)
	h.wantTip(origin, origin)
	h.wantLatest(origin, origin, false)
	if len(h.envelopes()) != 0 {
		t.Fatal("an invalid spend was published")
	}
}

func TestFollowFindsTheCurrentTipOfANewOrigin(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	v1 := h.move(o, 0, h.inscribed("v1"))
	moved := h.move(v1, 0, plain())
	h.chain.Mine(v1, moved)
	h.woc.set(origin, v1.TxID().String())
	h.woc.set(op(v1, 0), moved.TxID().String())

	h.track(origin)
	h.wantTip(origin, op(moved, 0))
	h.wantLatest(origin, op(v1, 0), false)
	if h.stat("ordtrack_pending") != 0 {
		t.Fatalf("mined links recorded as pending: %v", h.tr.Stats())
	}
}

func TestOnlyOriginsAreTracked(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.chain.Mine(v1)
	unmined := h.mint("u")
	unmined.MerklePath = nil

	// A later link of a chain, a change output and an unmined output are
	// not taken as origins. Only the later link, a mined 1-sat output, costs
	// an SPV check before its walk back refuses it.
	spvBefore := h.spvCalls.Load()
	h.track(op(v1, 0), op(o, 1), op(unmined, 0))
	if n := h.spvCalls.Load() - spvBefore; n != 1 {
		t.Fatalf("%d SPV checks, want 1", n)
	}
	for _, p := range []string{op(v1, 0), op(o, 1), op(unmined, 0)} {
		if _, _, err := h.tr.ResolveVersion(p, -1); !errors.Is(err, content.ErrNotTracked) {
			t.Fatalf("%s: err %v, want ErrNotTracked", p, err)
		}
	}
	h.tr.mu.Lock()
	refusedLink, refusedChange := h.tr.wanted[op(v1, 0)].refused, h.tr.wanted[op(o, 1)].refused
	retry := h.tr.wanted[op(unmined, 0)]
	h.tr.mu.Unlock()
	if !refusedLink || !refusedChange || retry.refused || retry.attempts != 1 {
		t.Fatalf("refused link %v, change %v; unmined %+v (want retried)", refusedLink, refusedChange, retry)
	}
}

func TestTrackedSetChanges(t *testing.T) {
	h := newHarness(t)
	a, b := h.mint("a"), h.mint("b")
	originA, originB := op(a, 0), op(b, 0)
	h.track(originA, originB)
	if h.watch.Len() != 2 {
		t.Fatalf("watched %d", h.watch.Len())
	}
	// Removing an origin stops watching it; its history stays a day.
	h.track(originB)
	if h.watch.Len() != 1 {
		t.Fatalf("watched %d after removing one", h.watch.Len())
	}
	if _, _, err := h.tr.ResolveVersion(originA, -1); !errors.Is(err, content.ErrNotTracked) {
		t.Fatalf("a removed origin is still served: %v", err)
	}
	h.track(originA, originB)
	h.wantLatest(originA, originA, false)
	h.track(originB)
	h.clock.advance(removedRetention + time.Minute)
	h.tr.dropRemoved()
	h.tr.mu.Lock()
	_, kept := h.tr.chains[originA]
	h.tr.mu.Unlock()
	if kept {
		t.Fatal("a removed origin's history outlived its retention")
	}
	if metas, err := h.tr.db.metas(); err != nil || len(metas) != 1 {
		t.Fatalf("stored chains %v, %v", metas, err)
	}
}

func TestTrackedOriginsAreCapped(t *testing.T) {
	h := newHarness(t)
	h.tr.cfg.MaxOrigins = 2
	a, b, c := h.mint("a"), h.mint("b"), h.mint("c")
	h.track(op(a, 0), op(b, 0), op(c, 0), "not an outpoint")
	if got := h.stat("ordtrack_origins"); got != 2 {
		t.Fatalf("tracked %d origins, want the cap of 2", got)
	}
}
