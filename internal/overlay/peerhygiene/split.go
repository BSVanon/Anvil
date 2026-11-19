package peerhygiene

import (
	"math/bits"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Why the proofs in a binary lookup answer are split, one per transaction.
//
// A node that aggregates a lookup answer (ts-stack, and Anvil's own
// writeAggregatedAnswer) merges the outputs' BEEFs into one shared BEEF, and
// Beef.MergeBump folds every proof from the same block into one compound
// BUMP. go-sdk v1.7.7's facilitator then rebuilds each output's BEEF with
// Transaction.BEEF, which writes the whole BUMP a transaction points to. So n
// outputs mined in one block each carry the proofs of all n, and the answer
// grows as n squared: 70 advertisements mined in one block of 2^20
// transactions came to 2.76 MB, against a shared BEEF of some 100 KB.
//
// splitProofs undoes the merge before any output is rebuilt. Each
// transaction proven by a BUMP that holds more than its own path gets a BUMP
// of its own, with only its own path, which is the proof its submitter sent
// in the first place. A split path is used only when go-sdk computes the
// same merkle root from it as from the BUMP it came from; a transaction
// whose path cannot be rebuilt keeps the shared BUMP. The split hashes each
// node of a BUMP once at most and does a tree height of lookups per
// transaction, so it is linear in the shared BEEF.
func splitProofs(beef *transaction.Beef) {
	proven := make(map[*transaction.MerklePath][]*transaction.Transaction)
	ids := make(map[*transaction.Transaction]chainhash.Hash)
	for txid, btx := range beef.Transactions {
		if btx == nil || btx.Transaction == nil || btx.Transaction.MerklePath == nil {
			continue
		}
		mp := btx.Transaction.MerklePath
		proven[mp] = append(proven[mp], btx.Transaction)
		ids[btx.Transaction] = txid
	}
	for mp, txs := range proven {
		if !holdsMoreThanOnePath(mp) {
			continue
		}
		root, err := mp.ComputeRoot(nil)
		if err != nil {
			continue
		}
		index := newPathIndex(mp)
		for _, tx := range txs {
			txid := ids[tx]
			own := index.pathFor(mp.BlockHeight, &txid)
			if own == nil {
				continue
			}
			if got, err := own.ComputeRoot(&txid); err != nil || !got.IsEqual(root) {
				continue
			}
			tx.MerklePath = own
		}
	}
}

// holdsMoreThanOnePath reports whether mp has more elements than the path of
// a single transaction: two at the bottom level and one at each level above.
func holdsMoreThanOnePath(mp *transaction.MerklePath) bool {
	for h, level := range mp.Path {
		if (h == 0 && len(level) > 2) || (h > 0 && len(level) > 1) {
			return true
		}
	}
	return false
}

// pathIndex looks up the nodes of one BUMP by level and offset, as go-sdk's
// IndexedPath.GetOffsetLeaf does, synthesizing a missing node from its two
// children, but it remembers every node it synthesizes, and every miss, so
// that no node is hashed twice however many transactions share the BUMP.
type pathIndex struct {
	levels    []map[uint64]*transaction.PathElement
	made      map[nodeKey]*transaction.PathElement
	firstLeaf map[chainhash.Hash]*transaction.PathElement
	maxLeaf   uint64 // the largest offset at the bottom level
}

type nodeKey struct {
	level  int
	offset uint64
}

func newPathIndex(mp *transaction.MerklePath) *pathIndex {
	x := &pathIndex{
		levels:    make([]map[uint64]*transaction.PathElement, len(mp.Path)),
		made:      make(map[nodeKey]*transaction.PathElement),
		firstLeaf: make(map[chainhash.Hash]*transaction.PathElement),
	}
	for h, level := range mp.Path {
		m := make(map[uint64]*transaction.PathElement, len(level))
		for _, el := range level {
			m[el.Offset] = el // a later element wins, as in go-sdk
		}
		x.levels[h] = m
	}
	for _, el := range mp.Path[0] {
		if el.Offset > x.maxLeaf {
			x.maxLeaf = el.Offset
		}
		// ComputeRoot proves a txid from the first bottom-level element
		// that carries it.
		if el.Hash != nil {
			if _, seen := x.firstLeaf[*el.Hash]; !seen {
				x.firstLeaf[*el.Hash] = el
			}
		}
	}
	return x
}

// node returns the element at level and offset, given or synthesized, or nil
// when the BUMP cannot supply it. It follows IndexedPath.GetOffsetLeaf in
// go-sdk v1.7.7 step for step.
func (x *pathIndex) node(level int, offset uint64) *transaction.PathElement {
	if level < len(x.levels) {
		if el, ok := x.levels[level][offset]; ok {
			return el
		}
	}
	if level == 0 {
		return nil
	}
	key := nodeKey{level, offset}
	if el, ok := x.made[key]; ok {
		return el
	}
	el := x.synthesize(level, offset)
	x.made[key] = el
	return el
}

func (x *pathIndex) synthesize(level int, offset uint64) *transaction.PathElement {
	left := x.node(level-1, offset*2)
	if left == nil || left.Hash == nil {
		return nil
	}
	right := x.node(level-1, offset*2+1)
	if right == nil || right.Hash == nil {
		if right != nil && right.Duplicate != nil && *right.Duplicate {
			return &transaction.PathElement{Offset: offset, Hash: transaction.MerkleTreeParent(left.Hash, left.Hash)}
		}
		// A BUMP of the bottom level alone hashes the last node of an odd
		// level with itself, though it marks no duplicate.
		if len(x.levels) == 1 && offset*2 == x.maxLeaf>>uint(level-1) {
			return &transaction.PathElement{Offset: offset, Hash: transaction.MerkleTreeParent(left.Hash, left.Hash)}
		}
		return nil
	}
	if right.Duplicate != nil && *right.Duplicate {
		return &transaction.PathElement{Offset: offset, Hash: transaction.MerkleTreeParent(left.Hash, left.Hash)}
	}
	return &transaction.PathElement{Offset: offset, Hash: transaction.MerkleTreeParent(left.Hash, right.Hash)}
}

// pathFor builds the single-transaction BUMP for txid: the txid's own
// element and its sibling at the bottom level, then the sibling of its
// ancestor at each level above, up to the height ComputeRoot climbs. It
// returns nil when the BUMP does not hold txid or lacks a sibling.
func (x *pathIndex) pathFor(blockHeight uint32, txid *chainhash.Hash) *transaction.MerklePath {
	leaf, ok := x.firstLeaf[*txid]
	if !ok {
		return nil
	}
	height := len(x.levels)
	if h := bits.Len64(x.maxLeaf); h > height {
		height = h
	}
	path := make([][]*transaction.PathElement, height)
	for h := 0; h < height; h++ {
		sibling := x.node(h, (leaf.Offset>>uint(h))^1)
		if sibling == nil {
			return nil
		}
		el := &transaction.PathElement{Offset: sibling.Offset, Hash: sibling.Hash, Duplicate: sibling.Duplicate}
		if h > 0 {
			path[h] = []*transaction.PathElement{el}
			continue
		}
		own := &transaction.PathElement{Offset: leaf.Offset, Hash: leaf.Hash, Txid: leaf.Txid}
		if el.Offset < own.Offset {
			path[0] = []*transaction.PathElement{el, own}
		} else {
			path[0] = []*transaction.PathElement{own, el}
		}
	}
	return transaction.NewMerklePath(blockHeight, path)
}
