package ordtrack

import (
	"context"
	"errors"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// verifyTx runs the verifier on x as a spend of tip, from x's BEEF when
// withBEEF is set and from the store otherwise.
func (h *harness) verifyTx(tip string, x *transaction.Transaction, withBEEF bool, trusted map[string]bool, fetch bool) (*spend, error) {
	h.t.Helper()
	c := candidate{origin: tip, tip: tip, txid: x.TxID().String()}
	if withBEEF {
		c.beef = h.beefOf(x)
	}
	if trusted == nil {
		trusted = map[string]bool{}
	}
	return h.tr.v.verify(h.ctx, c, trusted, fetch)
}

func (h *harness) beefOf(x *transaction.Transaction) *beefnorm.BEEF {
	h.t.Helper()
	n, err := parseBEEF(ordtracktest.AtomicBEEF(h.t, x))
	if err != nil {
		h.t.Fatal(err)
	}
	return n
}

func TestVerifyAcceptsAnHonestTransfer(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	x := h.move(o, 0, h.inscribed("v1"))
	for _, withBEEF := range []bool{false, true} {
		s, err := h.verifyTx(op(o, 0), x, withBEEF, nil, !withBEEF)
		if err != nil {
			t.Fatalf("BEEF %v: %v", withBEEF, err)
		}
		if s.kind != Transfer || s.vout != 0 || !s.inscribed || s.contentType != "text/plain" || s.mined {
			t.Fatalf("BEEF %v: spend = %+v", withBEEF, s)
		}
	}
	h.chain.Mine(x)
	s, err := h.verifyTx(op(o, 0), x, false, nil, true)
	if err != nil || !s.mined || s.height == 0 || s.kind != Transfer {
		t.Fatalf("mined: spend %+v, err %v", s, err)
	}
}

func TestVerifyRefusesAForgedInputValue(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	// An unmined funding transaction that pays more than it spends: its
	// 50,000-sat output puts the token's sat at #50,001, which lands in the
	// attacker's 1-sat output. Nothing proves that value; spv.Verify checks
	// the parent whole and refuses it.
	small := h.fund(1_000)
	inflated := h.w.Spend(t, []ordtracktest.In{{Tx: small}}, ordtracktest.Out{Sats: 50_000})
	h.store.Add(inflated)
	x := h.w.Spend(t, []ordtracktest.In{{Tx: inflated}, {Tx: o}}, ordtracktest.Out{Sats: 50_000}, h.inscribed("forged"))
	h.store.Add(x)
	for _, withBEEF := range []bool{false, true} {
		if s, err := h.verifyTx(op(o, 0), x, withBEEF, nil, !withBEEF); !errors.Is(err, errInvalid) {
			t.Fatalf("BEEF %v: inflated parent: spend %+v, err %v; want errInvalid", withBEEF, s, err)
		}
	}

	// A fetch path that answers with other bytes than the txid's.
	honest := h.move(o, 0, h.inscribed("v1"))
	lying := &swapSource{source: h.src, swap: map[string]*transaction.Transaction{honest.Inputs[1].SourceTXID.String(): inflated}}
	h.tr.v.source = lying
	if s, err := h.verifyTx(op(o, 0), honest, false, nil, true); !errors.Is(err, errInvalid) {
		t.Fatalf("source answering with another transaction: spend %+v, err %v; want errInvalid", s, err)
	}
}

// A spend that says it is mined has its scripts and input values taken as
// consensus checked them, so it needs a merkle path the node's headers
// confirm: from the fetch path, from its BEEF, and on the credential path,
// which fetches nothing.
func TestVerifyRefusesAnUnprovenMinedClaim(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	x := h.moveBy(ordtracktest.NewWallet(t), o, 0, h.inscribed("stolen"))
	ordtracktest.NewChain().Mine(x) // a block these headers do not hold
	for _, c := range []struct{ withBEEF, fetch bool }{{false, true}, {true, true}, {true, false}} {
		if s, err := h.verifyTx(op(o, 0), x, c.withBEEF, nil, c.fetch); !errors.Is(err, errInvalid) {
			t.Fatalf("BEEF %v, fetch %v: spend %+v, err %v; want errInvalid", c.withBEEF, c.fetch, s, err)
		}
	}
}

// A mined spend's input values are read as fetched, not proven by a script
// run, so a fetch path answering with another transaction's bytes is
// refused outright rather than moving the sat's position.
func TestVerifyRefusesAMinedSpendReadThroughALyingSource(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	small := h.fund(1_000)
	inflated := h.w.Spend(t, []ordtracktest.In{{Tx: h.fund(60_000)}}, ordtracktest.Out{Sats: 50_000})
	h.store.Add(inflated)
	x := h.w.Spend(t, []ordtracktest.In{{Tx: small}, {Tx: o}}, ordtracktest.Out{Sats: 1_000}, h.inscribed("v1"))
	h.chain.Mine(x)
	h.store.Add(x)
	if s, err := h.verifyTx(op(o, 0), x, false, nil, true); err != nil || s.kind != Transfer || s.vout != 1 {
		t.Fatalf("honest: spend %+v, err %v", s, err)
	}
	h.tr.v.source = &swapSource{source: h.src, swap: map[string]*transaction.Transaction{small.TxID().String(): inflated}}
	if s, err := h.verifyTx(op(o, 0), x, false, nil, true); !errors.Is(err, errInvalid) {
		t.Fatalf("lying source: spend %+v, err %v; want errInvalid", s, err)
	}
}

// swapSource answers some txids with another transaction's bytes.
type swapSource struct {
	*source
	swap map[string]*transaction.Transaction
}

func (s *swapSource) Tx(ctx context.Context, txid string) (*transaction.Transaction, error) {
	if tx := s.swap[txid]; tx != nil {
		return s.source.Tx(ctx, tx.TxID().String())
	}
	return s.source.Tx(ctx, txid)
}

func TestVerifyRefusesABadUnlockingScript(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	other := ordtracktest.NewWallet(t)

	// The token input signed by the wrong key: refused by the one script run
	// against the tip, before spv.Verify and before any other fetch.
	x := h.moveBy(other, o, 0, h.inscribed("stolen"))
	before := h.store.Calls.Load()
	if s, err := h.verifyTx(op(o, 0), x, false, nil, true); !errors.Is(err, errInvalid) {
		t.Fatalf("wrong key on the token input: spend %+v, err %v", s, err)
	}
	if n := h.spvCalls.Load(); n != 0 {
		t.Fatalf("spv.Verify ran %d times; the token input's script check must refuse first", n)
	}
	if n := h.store.Calls.Load() - before; n != 2 {
		t.Fatalf("%d fetches; want 2, the candidate and the tip's transaction", n)
	}
	if s, err := h.verifyTx(op(o, 0), x, true, nil, false); !errors.Is(err, errInvalid) || h.spvCalls.Load() != 0 {
		t.Fatalf("from its BEEF: spend %+v, err %v, spv calls %d", s, err, h.spvCalls.Load())
	}

	// A funding input whose script fails: spv.Verify refuses the whole
	// transaction.
	theirs := other.Fund(ordtracktest.Out{Sats: 10_000})
	h.chain.Mine(theirs)
	h.store.Add(theirs)
	y := h.w.Spend(t, []ordtracktest.In{{Tx: o}, {Tx: theirs}}, h.inscribed("v1"), ordtracktest.Out{Sats: 9_000})
	h.store.Add(y)
	if s, err := h.verifyTx(op(o, 0), y, false, nil, true); !errors.Is(err, errInvalid) {
		t.Fatalf("wrong key on the funding input: spend %+v, err %v", s, err)
	}
	if h.spvCalls.Load() != 1 {
		t.Fatalf("spv calls = %d, want 1", h.spvCalls.Load())
	}
}

func TestVerifyUnminedAncestryOneLevelDeep(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	f := h.fund(10_000)
	p1 := h.w.Spend(t, []ordtracktest.In{{Tx: f}}, ordtracktest.Out{Sats: 9_000})
	p2 := h.w.Spend(t, []ordtracktest.In{{Tx: p1}}, ordtracktest.Out{Sats: 8_000})
	h.store.Add(p1, p2)

	// An unmined parent whose own parents are mined: verified.
	one := h.w.Spend(t, []ordtracktest.In{{Tx: p1}, {Tx: o}}, ordtracktest.Out{Sats: 9_000}, h.inscribed("v1"))
	h.store.Add(one)
	if s, err := h.verifyTx(op(o, 0), one, false, nil, true); err != nil || s.kind != Transfer || s.vout != 1 {
		t.Fatalf("one unmined level: spend %+v, err %v", s, err)
	}
	// Two unmined levels: retry later, from the store and from a BEEF.
	two := h.w.Spend(t, []ordtracktest.In{{Tx: p2}, {Tx: o}}, ordtracktest.Out{Sats: 8_000}, h.inscribed("v1"))
	h.store.Add(two)
	for _, withBEEF := range []bool{false, true} {
		if s, err := h.verifyTx(op(o, 0), two, withBEEF, nil, !withBEEF); !errors.Is(err, errRetryLater) {
			t.Fatalf("BEEF %v: two unmined levels: spend %+v, err %v; want errRetryLater", withBEEF, s, err)
		}
	}
	// Unless the deeper one is a chain link already verified.
	if s, err := h.verifyTx(op(o, 0), two, false, map[string]bool{p1.TxID().String(): true}, true); err != nil || s.kind != Transfer {
		t.Fatalf("trusted grandparent: spend %+v, err %v", s, err)
	}
}

func TestVerifyFollowsAChainOfUnminedLinksThroughTrust(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	l1 := h.move(o, 0, h.inscribed("v1"))
	l2 := h.move(l1, 0, plain())
	l3 := h.move(l2, 0, h.inscribed("v3"))
	if _, err := h.verifyTx(op(l2, 0), l3, false, nil, true); !errors.Is(err, errRetryLater) {
		t.Fatalf("untrusted unmined grandparent: err %v, want errRetryLater", err)
	}
	trusted := map[string]bool{l1.TxID().String(): true, l2.TxID().String(): true}
	if s, err := h.verifyTx(op(l2, 0), l3, false, trusted, true); err != nil || s.kind != Transfer || !s.inscribed {
		t.Fatalf("trusted links: spend %+v, err %v", s, err)
	}
}

func TestVerifyRefusesWhatIsNotASpendOfTheTip(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	x := h.move(o, 0, h.inscribed("v1"))
	if _, err := h.verifyTx(op(o, 1), x, false, nil, true); !errors.Is(err, errInvalid) {
		t.Fatalf("a transaction that does not spend the tip: err %v", err)
	}
	if _, err := h.verifyTx(op(o, 0), x, false, nil, false); !errors.Is(err, errRetryLater) {
		t.Fatalf("nothing to fetch from: err %v, want errRetryLater", err)
	}
	// A mined transaction whose merkle path the headers do not hold.
	y := h.move(o, 0, h.inscribed("v1"))
	other := ordtracktest.NewChain()
	other.Mine(y)
	h.store.Add(y)
	if _, err := h.verifyTx(op(o, 0), y, false, nil, true); !errors.Is(err, errInvalid) {
		t.Fatalf("an unproven merkle path: err %v", err)
	}
}

func TestVerifyRefusesTooManyInputs(t *testing.T) {
	h := newHarness(t)
	o := h.mint("v0")
	x := h.move(o, 0, h.inscribed("v1"))
	wide := transaction.NewTransaction()
	wide.Inputs = append(wide.Inputs, x.Inputs[0])
	for len(wide.Inputs) <= maxInputs {
		wide.Inputs = append(wide.Inputs, x.Inputs[1])
	}
	wide.Outputs = x.Outputs
	h.store.Add(wide)
	if _, err := h.verifyTx(op(o, 0), wide, false, nil, true); !errors.Is(err, errInvalid) {
		t.Fatalf("%d inputs: err %v, want errInvalid", len(wide.Inputs), err)
	}
}
