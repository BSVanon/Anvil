package beefnorm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// tsAccepts checks p against the rules ts-sdk 2.0.4's MerklePath constructor
// enforces on every path it reads (MerklePath.ts:143-180): no offset twice on
// a level, every node above level 0 at an offset some non-duplicate level-0
// leaf's proof reads, and one root for every level-0 leaf.
func tsAccepts(t *testing.T, p *transaction.MerklePath) {
	t.Helper()
	legal := make([]map[uint64]bool, len(p.Path))
	for h := range legal {
		legal[h] = map[uint64]bool{}
	}
	for h, level := range p.Path {
		seen := map[uint64]bool{}
		for _, el := range level {
			if seen[el.Offset] {
				t.Fatalf("offset %d twice at level %d", el.Offset, h)
			}
			seen[el.Offset] = true
			if h == 0 && !duplicate(el) {
				for up := 1; up < len(p.Path); up++ {
					legal[up][(el.Offset>>uint(up))^1] = true //nolint:gosec // up > 0
				}
			}
			if h > 0 && !legal[h][el.Offset] {
				t.Fatalf("offset %d at level %d is no level-0 leaf's sibling", el.Offset, h)
			}
		}
	}
	root, err := p.ComputeRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, el := range p.Path[0] {
		if el.Hash == nil {
			continue
		}
		if r, err := p.ComputeRoot(el.Hash); err != nil || !r.IsEqual(root) {
			t.Fatalf("leaf %d: root %v (%v), want %s", el.Offset, r, err, root)
		}
	}
}

// TestCanonical_HoldsEverySiblingOfEachKeptTxid: the trimmed compound path an
// honest wallet sends for 64 parents of one block becomes the union of their
// single proofs, every txid's sibling at every level held, so verifying a
// txid computes no node; ts-sdk's rules accept it, and it verifies.
func TestCanonical_HoldsEverySiblingOfEachKeptTxid(t *testing.T) {
	subject, parents, blk := beefnormtest.Consolidation(64, 16, 700000)
	n, err := Parse(beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{parents[0].MerklePath}, parents...))
	if err != nil {
		t.Fatal(err)
	}
	if !n.Changed || len(n.Beef.BUMPs) != 1 {
		t.Fatalf("changed %v, %d BUMPs", n.Changed, len(n.Beef.BUMPs))
	}
	p := n.Beef.BUMPs[0]
	want := make([]map[uint64]bool, len(p.Path))
	for h := range want {
		want[h] = map[uint64]bool{}
	}
	for _, parent := range parents {
		var o uint64
		for _, el := range p.Path[0] {
			if el.Hash.IsEqual(parent.TxID()) {
				o = el.Offset
				if el.Txid == nil || !*el.Txid {
					t.Errorf("%s is not flagged as a txid", parent.TxID())
				}
			}
		}
		want[0][o] = true
		for h := range want {
			want[h][(o>>uint(h))^1] = true //nolint:gosec // h >= 0
		}
	}
	for h, level := range p.Path {
		if len(level) != len(want[h]) {
			t.Errorf("level %d holds %d nodes, want %d", h, len(level), len(want[h]))
		}
		for _, el := range level {
			if !want[h][el.Offset] {
				t.Errorf("level %d holds offset %d, which no kept txid's proof reads", h, el.Offset)
			}
			if h == 0 && el.Txid != nil && *el.Txid && n.Beef.Transactions[*el.Hash] == nil {
				t.Errorf("offset %d is flagged as a txid the BEEF does not hold", el.Offset)
			}
		}
	}
	tsAccepts(t, p)
	if ok, err := spv.Verify(context.Background(), n.Tx, beefnormtest.Tracker{}.Add(blk), nil); !ok || err != nil {
		t.Errorf("spv.Verify: %v %v", ok, err)
	}
}

// six is the path of the transaction at offset 4 or 5 of a block of six,
// leaves t4 and t5, whose node at level 1, offset 2 is unpaired: its sibling
// at offset 3 is either a duplicate mark or, as no honest proof writes it, a
// hash equal to it. Both give one root.
func six(t4, t5 *chainhash.Hash, txidAt uint64, markDuplicate bool) *transaction.MerklePath {
	yes := true
	n20 := chainhash.Hash{20}
	w := transaction.MerkleTreeParent(t4, t5)
	l0 := []*transaction.PathElement{{Offset: 4, Hash: t4}, {Offset: 5, Hash: t5}}
	l0[txidAt-4].Txid = &yes
	sibling := &transaction.PathElement{Offset: 3, Hash: w}
	if markDuplicate {
		sibling = &transaction.PathElement{Offset: 3, Duplicate: &yes}
	}
	return transaction.NewMerklePath(700001, [][]*transaction.PathElement{l0, {sibling}, {{Offset: 0, Hash: &n20}}})
}

// TestCanonical_RefusesProofsThatDisagreeAtANode: two BUMPs of one block,
// one proving the transaction at offset 4 and marking the unpaired node's
// sibling a duplicate, the other proving the one at offset 5 and writing that
// sibling as a hash. Their roots agree; the node they share does not.
func TestCanonical_RefusesProofsThatDisagreeAtANode(t *testing.T) {
	p4, p5 := beefnormtest.Parent(30, 1, 1000), beefnormtest.Parent(31, 1, 1000)
	p4.MerklePath, p5.MerklePath = six(p4.TxID(), p5.TxID(), 4, true), six(p4.TxID(), p5.TxID(), 5, false)
	r4, err4 := p4.MerklePath.ComputeRoot(nil)
	r5, err5 := p5.MerklePath.ComputeRoot(nil)
	if err4 != nil || err5 != nil || !r4.IsEqual(r5) {
		t.Fatalf("roots %v (%v) and %v (%v), want one root", r4, err4, r5, err5)
	}
	s := beefnormtest.Spend(p4, p5)
	_, err := Parse(beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p4.MerklePath, p5.MerklePath}, p4, p5))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "disagree at level 1, offset 3") {
		t.Errorf("got %v, want the refusal of proofs that disagree at a node", err)
	}
}

// TestCanonical_KeepsTheProofOfABlockOfOneTransaction: the proof of a block
// whose only transaction is the parent is the one leaf, which is the root,
// with no sibling to read; it is kept as it is and verifies.
func TestCanonical_KeepsTheProofOfABlockOfOneTransaction(t *testing.T) {
	yes := true
	parent := beefnormtest.Parent(40, 1, 1000)
	parent.MerklePath = transaction.NewMerklePath(700002, [][]*transaction.PathElement{{{Offset: 0, Hash: parent.TxID(), Txid: &yes}}})
	s := beefnormtest.Spend(parent)
	for _, version := range []uint32{transaction.BEEF_V1, transaction.BEEF_V2} {
		n, err := Parse(beefnormtest.Encode(t, version, s, []*transaction.MerklePath{parent.MerklePath}, parent))
		if err != nil {
			t.Fatalf("version %x: %v", version, err)
		}
		if n.Changed {
			t.Errorf("version %x: the proof of a block of one transaction was changed", version)
		}
		tracker := beefnormtest.Tracker{700002: parent.TxID()}
		if ok, err := spv.Verify(context.Background(), n.Tx, tracker, nil); !ok || err != nil {
			t.Errorf("version %x: spv.Verify: %v %v", version, ok, err)
		}
	}
}

// TestCanonical_ClimbsFromTheFirstLeafOfAHash: when one hash is at two
// leaves of a path, as no valid block has but a client can write, the txid
// is kept at the first, the leaf ComputeRoot climbs from, and a path already
// flagging that one is left as it is.
func TestCanonical_ClimbsFromTheFirstLeafOfAHash(t *testing.T) {
	yes := true
	parent := beefnormtest.Parent(41, 1, 1000)
	id := parent.TxID()
	parent.MerklePath = transaction.NewMerklePath(700003, [][]*transaction.PathElement{{{Offset: 0, Hash: id, Txid: &yes}, {Offset: 1, Hash: id}}})
	n, err := Parse(beefnormtest.Encode(t, transaction.BEEF_V2, beefnormtest.Spend(parent), []*transaction.MerklePath{parent.MerklePath}, parent))
	if err != nil {
		t.Fatal(err)
	}
	if n.Changed {
		l := n.Beef.BUMPs[0].Path[0]
		t.Errorf("changed: level 0 flags %v at offset 0 and %v at offset 1", l[0].Txid != nil, l[1].Txid != nil)
	}
}

// TestBlock_RefusesAProofMissingANode: a path that names a txid but holds no
// node for its sibling at level 1, nor what it is computed from, is refused,
// as is a txid the path does not flag. Extract's root check refuses every
// such path Parse has met, so this is the guard behind it, tested on a path
// built directly.
func TestBlock_RefusesAProofMissingANode(t *testing.T) {
	yes := true
	a, x := chainhash.Hash{1}, chainhash.Hash{2}
	path := transaction.NewMerklePath(1, [][]*transaction.PathElement{{{Offset: 0, Hash: &a, Txid: &yes}, {Offset: 1, Hash: &x}}, {}})
	err := newBlock(0, 0, 1, &a, 2).add(path, []*chainhash.Hash{&a})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "has no node at level 1, offset 1") {
		t.Errorf("a missing node: %v", err)
	}
	err = newBlock(0, 0, 1, &a, 2).add(path, []*chainhash.Hash{&x})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "does not hold it") {
		t.Errorf("a txid the path does not flag: %v", err)
	}
}
