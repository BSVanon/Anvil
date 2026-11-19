package beefnorm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// mine gives each tx a proof in a fresh block at height number of 2^levels
// transactions, at offsets 5, 6, ..., and returns the block.
func mine(number uint32, levels int, txs ...*transaction.Transaction) *beefnormtest.Block {
	ids := make([]*chainhash.Hash, len(txs))
	offsets := make([]uint64, len(txs))
	for i, tx := range txs {
		ids[i], offsets[i] = tx.TxID(), uint64(5+i) //nolint:gosec // i >= 0
	}
	blk := beefnormtest.NewBlock(number, levels, ids, offsets)
	for i, tx := range txs {
		tx.MerklePath = blk.Proof(i)
	}
	return blk
}

// ts210 is the Atomic BEEF ts-sdk 2.1.0's Beef.getBeefForAtomic writes for s,
// a subject spending the proven parent p, out of a BEEF that also held u1, an
// unrelated proven transaction, and u2, an unrelated unproven one spending the
// proven u3: it trims only what is newer than s, so all of them stay.
func ts210(t *testing.T) (b []byte, s, p *transaction.Transaction, unrelated []*transaction.Transaction, tracker beefnormtest.Tracker) {
	t.Helper()
	p, u1, u3 := beefnormtest.Parent(1, 1, 1000), beefnormtest.Parent(2, 1, 1000), beefnormtest.Parent(3, 1, 1000)
	tracker = beefnormtest.Tracker{}.Add(mine(800000, 10, p), mine(800001, 10, u1), mine(800002, 10, u3))
	u2, s := beefnormtest.Spend(u3), beefnormtest.Spend(p)
	inner := beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p.MerklePath, u1.MerklePath, u3.MerklePath}, p, u1, u3, u2)
	return beefnormtest.Atomic(s, inner), s, p, []*transaction.Transaction{u1, u2, u3}, tracker
}

// holdsOnly checks that b, a BEEF in any format, holds exactly want.
func holdsOnly(t *testing.T, b []byte, want ...*transaction.Transaction) {
	t.Helper()
	inner := b
	if binary.LittleEndian.Uint32(b) == transaction.ATOMIC_BEEF {
		inner = b[36:]
	}
	parsed, err := transaction.NewBeefFromBytes(inner)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Transactions) != len(want) {
		t.Errorf("%d entries, want %d", len(parsed.Transactions), len(want))
	}
	for _, tx := range want {
		if parsed.FindTransactionByHash(tx.TxID()) == nil {
			t.Errorf("%s missing", tx.TxID())
		}
	}
}

func TestParse_KeepsOnlyTheSubjectsGraph(t *testing.T) {
	b, s, p, unrelated, tracker := ts210(t)
	if _, _, err := transaction.NewBeefFromAtomicBytes(b); err == nil || !strings.Contains(err.Error(), "outside the dependency graph") {
		t.Fatalf("go-sdk's own parse: %v, want its BRC-95 refusal", err)
	}
	n, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if n.Format != transaction.ATOMIC_BEEF || !n.Changed || !n.Subject.IsEqual(s.TxID()) {
		t.Errorf("format %x, changed %v, subject %s", n.Format, n.Changed, n.Subject)
	}
	if len(n.Beef.Transactions) != 2 || len(n.Beef.BUMPs) != 1 || n.Beef.BUMPs[0].BlockHeight != 800000 {
		t.Errorf("kept %d entries and %d BUMPs, want the subject, its parent and the parent's BUMP", len(n.Beef.Transactions), len(n.Beef.BUMPs))
	}
	for _, u := range unrelated {
		if n.Beef.FindTransactionByHash(u.TxID()) != nil {
			t.Errorf("unrelated %s kept", u.TxID())
		}
	}
	if ok, err := spv.Verify(context.Background(), n.Tx, tracker, nil); !ok || err != nil {
		t.Errorf("spv.Verify: %v %v", ok, err)
	}
	out, err := n.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := transaction.NewBeefFromAtomicBytes(out); err != nil {
		t.Errorf("go-sdk refuses what Bytes wrote: %v", err)
	}
	if tx, err := transaction.NewTransactionFromBEEF(out); err != nil || !tx.TxID().IsEqual(s.TxID()) {
		t.Errorf("NewTransactionFromBEEF of what Bytes wrote: %v", err)
	}
	holdsOnly(t, out, s, p)
	atomic, err := n.Atomic()
	if err != nil {
		t.Fatal(err)
	}
	holdsOnly(t, atomic, s, p)
}

// TestParse_DropsTheAncestryOfProvenTransactions: a proven parent's own
// unproven parent, and that one's BUMP, which nothing verifies, are dropped,
// and the parent's input is no longer linked to it.
func TestParse_DropsTheAncestryOfProvenTransactions(t *testing.T) {
	r := beefnormtest.Parent(4, 1, 1000)
	mine(700000, 8, r) // a block the tracker does not know: its proof is never checked
	q := beefnormtest.Spend(r)
	p := beefnormtest.Spend(q)
	tracker := beefnormtest.Tracker{}.Add(mine(700001, 8, p))
	s := beefnormtest.Spend(p)
	for _, v := range []uint32{transaction.BEEF_V1, transaction.BEEF_V2} {
		n, err := Parse(beefnormtest.Encode(t, v, s, []*transaction.MerklePath{r.MerklePath, p.MerklePath}, r, q, p))
		if err != nil {
			t.Fatalf("version %x: %v", v, err)
		}
		if len(n.Beef.Transactions) != 2 || len(n.Beef.BUMPs) != 1 || !n.Changed {
			t.Errorf("version %x: kept %d entries, %d BUMPs, changed %v", v, len(n.Beef.Transactions), len(n.Beef.BUMPs), n.Changed)
		}
		kept := n.Beef.FindTransactionByHash(p.TxID())
		if kept.Inputs[0].SourceTransaction != nil {
			t.Errorf("version %x: the proven parent still links to its dropped source", v)
		}
		if ok, err := spv.Verify(context.Background(), n.Tx, tracker, nil); !ok || err != nil {
			t.Errorf("version %x: spv.Verify: %v %v", v, ok, err)
		}
	}
}

// entries writes a V2 BEEF of bumps and already-encoded entries, in order.
func entries(bumps []*transaction.MerklePath, es ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, transaction.BEEF_V2)
	b = append(b, util.VarInt(len(bumps)).Bytes()...)
	for _, p := range bumps {
		b = append(b, p.Bytes()...)
	}
	b = append(b, util.VarInt(len(es)).Bytes()...)
	for _, e := range es {
		b = append(b, e...)
	}
	return b
}

func raw(tx *transaction.Transaction) []byte { return append([]byte{0}, tx.Bytes()...) }

func proven(i byte, tx *transaction.Transaction) []byte { return append([]byte{1, i}, tx.Bytes()...) }

func txidOnly(tx *transaction.Transaction) []byte { return append([]byte{2}, tx.TxID()[:]...) }

func TestParse_RefusesATxidHeldTwice(t *testing.T) {
	p := beefnormtest.Parent(5, 1, 1000)
	mine(600000, 8, p)
	s := beefnormtest.Spend(p)
	bumps := []*transaction.MerklePath{p.MerklePath}
	for name, b := range map[string][]byte{
		"raw twice":          entries(bumps, proven(0, p), raw(p), raw(s)),
		"txid-only then raw": entries(bumps, txidOnly(p), proven(0, p), raw(s)),
		"raw then txid-only": entries(bumps, proven(0, p), txidOnly(p), raw(s)),
	} {
		if _, err := Parse(b); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "distinct txids") {
			t.Errorf("%s: %v, want the repeated-txid refusal", name, err)
		}
	}
	if _, err := Parse(entries(bumps, proven(0, p), raw(s))); err != nil {
		t.Errorf("each once: %v", err)
	}
}

func TestParse_NoSubject(t *testing.T) {
	p := beefnormtest.Parent(6, 1, 1000)
	mine(600001, 8, p)
	s := beefnormtest.Spend(p)
	bumps := []*transaction.MerklePath{p.MerklePath}
	v1Empty := append(binary.LittleEndian.AppendUint32(nil, transaction.BEEF_V1), 0, 0)
	for name, b := range map[string][]byte{
		"V1 with no transactions":        v1Empty,
		"V2 with no transactions":        entries(nil),
		"V2 ending in a bare txid":       entries(bumps, proven(0, p), txidOnly(s)),
		"Atomic naming a missing txid":   beefnormtest.Atomic(s, entries(bumps, proven(0, p))),
		"Atomic naming a bare txid":      beefnormtest.Atomic(s, entries(bumps, proven(0, p), txidOnly(s))),
		"Atomic naming no V1 subject":    beefnormtest.Atomic(s, v1Empty),
		"Atomic with nothing it wraps":   beefnormtest.Atomic(s, entries(nil)),
		"Atomic, its subject not raw V2": beefnormtest.Atomic(p, entries(bumps, txidOnly(p), raw(s))),
	} {
		if _, err := Parse(b); !errors.Is(err, ErrNoSubject) {
			t.Errorf("%s: %v, want ErrNoSubject", name, err)
		}
	}
	nested := beefnormtest.Atomic(s, beefnormtest.Atomic(s, entries(bumps, proven(0, p), raw(s))))
	if n, err := Parse(nested); err == nil || n != nil {
		t.Errorf("an Atomic BEEF wrapping another: %v", err)
	}
	if _, err := Parse(beefnormtest.Atomic(s, nil)[:20]); err == nil {
		t.Error("a cut-short Atomic header was accepted")
	}
}

func TestParse_RefusesAnEntryItsBUMPDoesNotHold(t *testing.T) {
	p, x := beefnormtest.Parent(7, 1, 1000), beefnormtest.Parent(8, 1, 1000)
	mine(600002, 8, x)
	s := beefnormtest.Spend(p)
	b := entries([]*transaction.MerklePath{x.MerklePath}, proven(0, p), raw(s))
	if _, err := Parse(b); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "does not hold it") {
		t.Errorf("got %v, want the refusal of an entry its BUMP does not hold", err)
	}
}

// TestParse_CompletesAShortProof: a single-level compound proof, which
// go-sdk accepts for a whole block's leaves, becomes a path with every level
// of the tree, which go-sdk can combine with any other proof of the block.
func TestParse_CompletesAShortProof(t *testing.T) {
	p := beefnormtest.Parent(9, 1, 1000)
	blk := beefnormtest.NewFullBlock(600003, 3, []*chainhash.Hash{p.TxID()}, []uint64{6})
	p.MerklePath = blk.Flat()
	if len(p.MerklePath.Path) != 1 {
		t.Fatalf("the flat proof has %d levels", len(p.MerklePath.Path))
	}
	tracker := beefnormtest.Tracker{}.Add(blk)
	s := beefnormtest.Spend(p)
	n, err := Parse(beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p.MerklePath}, p))
	if err != nil {
		t.Fatal(err)
	}
	got := n.Beef.BUMPs[0]
	if len(got.Path) != 3 || !n.Changed {
		t.Errorf("%d levels, changed %v; want the tree's 3", len(got.Path), n.Changed)
	}
	if root, err := got.ComputeRoot(p.TxID()); err != nil || !root.IsEqual(blk.Root()) {
		t.Errorf("root %v (%v), want %s", root, err, blk.Root())
	}
	if ok, err := spv.Verify(context.Background(), n.Tx, tracker, nil); !ok || err != nil {
		t.Errorf("spv.Verify: %v %v", ok, err)
	}
}

func TestParse_CombinesTheProofsOfOneBlock(t *testing.T) {
	p1, p2 := beefnormtest.Parent(10, 1, 1000), beefnormtest.Parent(11, 1, 1000)
	blk := mine(600004, 12, p1, p2)
	tracker := beefnormtest.Tracker{}.Add(blk)
	s := beefnormtest.Spend(p1, p2)
	n, err := Parse(beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p1.MerklePath, p2.MerklePath}, p1, p2))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Beef.BUMPs) != 1 || !n.Changed {
		t.Fatalf("%d BUMPs, changed %v; want one for the block", len(n.Beef.BUMPs), n.Changed)
	}
	for _, p := range []*transaction.Transaction{p1, p2} {
		e := n.Beef.Transactions[*p.TxID()]
		if e.BumpIndex != 0 || e.Transaction.MerklePath != n.Beef.BUMPs[0] {
			t.Errorf("%s: BUMP index %d, not the block's path", p.TxID(), e.BumpIndex)
		}
	}
	if ok, err := spv.Verify(context.Background(), n.Tx, tracker, nil); !ok || err != nil {
		t.Errorf("spv.Verify: %v %v", ok, err)
	}
}

// TestParse_RefusesProofsOfOneBlockThatDisagree: two proofs of one height
// with different roots, and two whose extracted paths have different
// heights, cannot be combined.
func TestParse_RefusesProofsOfOneBlockThatDisagree(t *testing.T) {
	p1, p2 := beefnormtest.Parent(12, 1, 1000), beefnormtest.Parent(13, 1, 1000)
	mine(600005, 10, p1)
	mine(600005, 10, p2) // the same height, another tree
	s := beefnormtest.Spend(p1, p2)
	b := beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p1.MerklePath, p2.MerklePath}, p1, p2)
	if _, err := Parse(b); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "different roots") {
		t.Errorf("different roots: %v", err)
	}
	// Both proofs declare one level, so beefscan sees no mixed levels, but
	// their offsets need 3 and 4.
	p1.MerklePath = beefnormtest.NewFullBlock(600006, 3, []*chainhash.Hash{p1.TxID()}, []uint64{2}).Flat()
	p2.MerklePath = beefnormtest.NewFullBlock(600006, 4, []*chainhash.Hash{p2.TxID()}, []uint64{9}).Flat()
	b = beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p1.MerklePath, p2.MerklePath}, p1, p2)
	if _, err := Parse(b); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "levels") {
		t.Errorf("different heights: %v", err)
	}
}

// TestParse_LeavesACanonicalBEEFAsItIs: a BEEF holding only the subject's
// graph, its one proof a single transaction's, which is canonical form, is
// unchanged, and Bytes returns it as received.
func TestParse_LeavesACanonicalBEEFAsItIs(t *testing.T) {
	p := beefnormtest.Parent(14, 1, 1000)
	mine(600007, 12, p)
	s := beefnormtest.Spend(p)
	v1 := beefnormtest.Encode(t, transaction.BEEF_V1, s, []*transaction.MerklePath{p.MerklePath}, p)
	v2 := beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p.MerklePath}, p)
	for name, b := range map[string][]byte{"V1": v1, "V2": v2, "Atomic": beefnormtest.Atomic(s, v2)} {
		n, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, err := n.Bytes()
		if err != nil || n.Changed || !bytes.Equal(out, b) {
			t.Errorf("%s: changed %v, Bytes equal %v (%v)", name, n.Changed, bytes.Equal(out, b), err)
		}
	}
}

func TestParse_V1StaysV1(t *testing.T) {
	p, u := beefnormtest.Parent(15, 1, 1000), beefnormtest.Parent(16, 1, 1000)
	mine(600008, 10, p)
	mine(600009, 10, u)
	s := beefnormtest.Spend(p)
	n, err := Parse(beefnormtest.Encode(t, transaction.BEEF_V1, s, []*transaction.MerklePath{u.MerklePath, p.MerklePath}, u, p))
	if err != nil {
		t.Fatal(err)
	}
	out, err := n.Bytes()
	if err != nil || binary.LittleEndian.Uint32(out) != transaction.BEEF_V1 {
		t.Fatalf("Bytes: %x (%v), want V1", out[:4], err)
	}
	if tx, err := transaction.NewTransactionFromBEEF(out); err != nil || !tx.TxID().IsEqual(s.TxID()) {
		t.Errorf("the V1 subject is not last: %v", err)
	}
	holdsOnly(t, out, s, p)
}
