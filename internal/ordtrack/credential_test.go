package ordtrack

import (
	"errors"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestVerifyTipUpdateFromTheBEEFAlone(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	if h.tr.Active() {
		t.Fatal("active with nothing tracked")
	}
	h.track(origin)
	if !h.tr.Active() {
		t.Fatal("not active with a tracked origin")
	}
	v1 := h.move(o, 0, h.inscribed("v1"))
	n := h.beefOf(v1)
	gotOrigin, tip, ok := h.tr.SpendsTip(n.Tx)
	if !ok || gotOrigin != origin || tip != origin {
		t.Fatalf("SpendsTip = %s %s %v", gotOrigin, tip, ok)
	}
	before := h.store.Calls.Load()
	accept, err := h.tr.VerifyTipUpdate(h.ctx, n, gotOrigin, tip)
	if err != nil {
		t.Fatal(err)
	}
	if n := h.store.Calls.Load() - before; n != 0 {
		t.Fatalf("%d fetches; the credential path reads only the BEEF", n)
	}
	h.wantTip(origin, origin) // nothing changes before accept
	accept()
	h.wantTip(origin, op(v1, 0))
	h.wantLatest(origin, op(v1, 0), true)
	if envs := h.envelopes(); len(envs) != 1 {
		t.Fatalf("published %d envelopes", len(envs))
	}
	if _, err := h.tr.VerifyTipUpdate(h.ctx, n, origin, origin); !errors.Is(err, errStaleTip) {
		t.Fatalf("the same update again: err %v, want errStaleTip", err)
	}
}

func TestVerifyTipUpdateTakesOnlyVerifiedTransfers(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	end := h.move(o, 0, ordtracktest.Out{Sats: 5_000})
	burn := h.burn(o, 0)
	stolen := h.moveBy(ordtracktest.NewWallet(t), o, 0, h.inscribed("stolen"))
	// Two spends only spv.Verify refuses: a funding parent that pays more
	// than it spends, which moves the token's sat into the attacker's 1-sat
	// output, and a funding input whose script fails.
	small := h.fund(1_000)
	inflated := h.w.Spend(t, []ordtracktest.In{{Tx: small}}, ordtracktest.Out{Sats: 50_000})
	forged := h.w.Spend(t, []ordtracktest.In{{Tx: inflated}, {Tx: o}}, ordtracktest.Out{Sats: 50_000}, h.inscribed("forged"))
	theirs := ordtracktest.NewWallet(t).Fund(ordtracktest.Out{Sats: 10_000})
	h.chain.Mine(theirs)
	badFunding := h.w.Spend(t, []ordtracktest.In{{Tx: o}, {Tx: theirs}}, h.inscribed("v1"), ordtracktest.Out{Sats: 9_000})
	spvBefore := h.spvCalls.Load()
	for name, c := range map[string]struct {
		tx   *transaction.Transaction
		want error
	}{
		"end": {end, errNotTransfer}, "burn": {burn, errNotTransfer}, "bad unlocking script": {stolen, errInvalid},
		"forged input value": {forged, errInvalid}, "bad funding script": {badFunding, errInvalid},
	} {
		if _, err := h.tr.VerifyTipUpdate(h.ctx, h.beefOf(c.tx), origin, origin); !errors.Is(err, c.want) {
			t.Fatalf("%s: err %v, want %v", name, err, c.want)
		}
	}
	if _, err := h.tr.VerifyTipUpdate(h.ctx, h.beefOf(end), op(end, 0), op(end, 0)); !errors.Is(err, errStaleTip) {
		t.Fatalf("an untracked origin: err %v", err)
	}
	if _, err := h.tr.VerifyTipUpdate(h.ctx, nil, origin, origin); !errors.Is(err, errInvalid) {
		t.Fatalf("no BEEF: err %v", err)
	}
	h.wantTip(origin, origin)
	if n := h.spvCalls.Load() - spvBefore; n != 4 {
		t.Fatalf("spv calls = %d; want 4: every spend but the one whose token input fails", n)
	}
}

func TestARolledBackSpendIsNoCredential(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.observe(v1)
	h.clock.advance(DefaultPendingTimeout)
	h.tr.checkPending(h.ctx)
	h.wantTip(origin, origin)
	if _, err := h.tr.VerifyTipUpdate(h.ctx, h.beefOf(v1), origin, origin); !errors.Is(err, errRolledBack) {
		t.Fatalf("err %v, want errRolledBack", err)
	}
}

func TestSpendsTipMatchesOnlyCurrentTips(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	v1 := h.move(o, 0, h.inscribed("v1"))
	if _, _, ok := h.tr.SpendsTip(v1); ok {
		t.Fatal("matched with nothing tracked")
	}
	h.track(origin)
	// The token input second: still found.
	f := h.fund(10_000)
	second := h.w.Spend(t, []ordtracktest.In{{Tx: f}, {Tx: o}}, ordtracktest.Out{Sats: 10_000}, plain())
	if got, _, ok := h.tr.SpendsTip(second); !ok || got != origin {
		t.Fatalf("token input second: %s %v", got, ok)
	}
	unrelated := h.w.Spend(t, []ordtracktest.In{{Tx: f}}, ordtracktest.Out{Sats: 9_000})
	if _, _, ok := h.tr.SpendsTip(unrelated); ok {
		t.Fatal("matched a transaction spending no tip")
	}
	wide := transaction.NewTransaction()
	for len(wide.Inputs) <= maxInputs {
		wide.Inputs = append(wide.Inputs, v1.Inputs[0])
	}
	if _, _, ok := h.tr.SpendsTip(wide); ok {
		t.Fatalf("matched a transaction of %d inputs", len(wide.Inputs))
	}
	if _, _, ok := h.tr.SpendsTip(nil); ok {
		t.Fatal("matched nil")
	}
}

func TestNoteBroadcastKeepsOnlyTipSpendsAndSavesTheFetch(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	origin := op(o, 0)
	h.track(origin)
	f := h.fund(10_000)
	unrelated := h.w.Spend(t, []ordtracktest.In{{Tx: f}}, ordtracktest.Out{Sats: 9_000})
	h.tr.NoteBroadcast(unrelated, ordtracktest.AtomicBEEF(t, unrelated))
	h.tr.NoteBroadcast(o, make([]byte, beefCacheEntry+1))
	if len(h.tr.beefs.byTxid) != 0 {
		t.Fatalf("kept %d BEEFs", len(h.tr.beefs.byTxid))
	}
	v1 := h.move(o, 0, h.inscribed("v1"))
	h.tr.NoteBroadcast(v1, ordtracktest.AtomicBEEF(t, v1))
	before := h.store.Calls.Load()
	h.observe(v1)
	h.wantLatest(origin, op(v1, 0), true)
	if n := h.store.Calls.Load() - before; n != 0 {
		t.Fatalf("%d fetches for a spend this node broadcast with its BEEF", n)
	}
}

func TestBeefCacheBounds(t *testing.T) {
	c := newBeefCache()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < beefCacheEntries+5; i++ {
		c.put(string(rune('a'+i%26))+string(rune('a'+i/26)), nil, []byte{1}, now)
	}
	if len(c.byTxid) != beefCacheEntries || len(c.order) != beefCacheEntries {
		t.Fatalf("%d entries, %d ordered; want %d", len(c.byTxid), len(c.order), beefCacheEntries)
	}
	big := make([]byte, beefCacheEntry)
	for i := 0; i < 9; i++ {
		c.put(string(rune('A'+i)), nil, big, now)
	}
	if c.bytes > beefCacheBytes {
		t.Fatalf("%d bytes kept, cap %d", c.bytes, beefCacheBytes)
	}
	c.put("old", nil, []byte{1}, now)
	if _, raw := c.take("old", now.Add(beefCacheTTL+1)); raw != nil {
		t.Fatal("an expired BEEF was returned")
	}
	if _, ok := c.byTxid["old"]; ok {
		t.Fatal("take left an expired BEEF")
	}
	c.put("too big", nil, make([]byte, beefCacheEntry+1), now)
	if _, ok := c.byTxid["too big"]; ok {
		t.Fatal("kept a BEEF over the per-entry cap")
	}
}
