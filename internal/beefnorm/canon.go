package beefnorm

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// canonicalize makes one BUMP per block for the kept entries and repoints
// each kept proven entry at its block's. The BUMP of a block holds, for each
// kept txid it proves, the txid and its sibling at every level of the
// block's tree, and nothing else: the union of their single proofs. The
// BUMP of a block of one transaction holds only its txid (see block.add).
//
// Each BUMP an entry names is first extracted for exactly the kept txids
// naming it (MerklePath.Extract, which v3engine's arc_ingest fullHeight uses
// to complete a short proof): Extract checks the extracted path's root
// against the BUMP's and gives it every level the tree has. The sibling at
// each level is then read from that path, or computed from it where it holds
// the sibling's children instead, as ComputeRoot computes it. A proof Extract
// refuses or that lacks a sibling is refused, as are proofs of one block with
// different roots, tree heights or nodes.
//
// So every node is one the verification of a kept txid reads directly:
// go-sdk v1.7.7's ComputeRoot finds it with a scan of its level, where on the
// minimal compound path Extract returns it would rebuild each node left out,
// hashing much of the tree again for every txid (merklepath.go:35-75,
// 100-122). changed reports a BUMP dropped, combined, renumbered or not
// already in this form.
func canonicalize(raw *transaction.Beef, kept map[chainhash.Hash]*transaction.BeefTx, named map[int][]*chainhash.Hash) ([]*transaction.MerklePath, bool, error) {
	order := make([]int, 0, len(named))
	for i := range named {
		order = append(order, i)
	}
	slices.Sort(order)
	var blocks []*block
	byHeight := make(map[uint32]*block)
	index := make(map[int]int, len(order)) // raw BUMP index -> index in blocks
	for _, i := range order {
		src := raw.BUMPs[i]
		ext, err := src.Extract(named[i])
		if err != nil {
			return nil, false, fmt.Errorf("%w: BUMP %d of block %d: %v", ErrRefused, i, src.BlockHeight, err)
		}
		root, err := ext.ComputeRoot(nil)
		if err != nil {
			return nil, false, fmt.Errorf("%w: BUMP %d of block %d: %v", ErrRefused, i, src.BlockHeight, err)
		}
		b := byHeight[src.BlockHeight]
		switch {
		case b == nil:
			b = newBlock(len(blocks), i, src.BlockHeight, root, len(ext.Path))
			byHeight[src.BlockHeight] = b
			blocks = append(blocks, b)
		// Stored paths of one block are combined later (the engine merges a
		// spent output's stored BEEF), and combining paths of different
		// heights panics in go-sdk v1.7.7 (combineVerified,
		// merklepath.go:468-480). Paths of different roots cannot both match
		// the block's header.
		case len(ext.Path) != b.levels:
			return nil, false, fmt.Errorf("%w: two proofs of block %d have %d and %d levels", ErrRefused, src.BlockHeight, b.levels, len(ext.Path))
		case !root.IsEqual(b.root):
			return nil, false, fmt.Errorf("%w: two proofs of block %d have different roots", ErrRefused, src.BlockHeight)
		default:
			b.sources++
		}
		if err := b.add(ext, named[i]); err != nil {
			return nil, false, err
		}
		index[i] = b.n
	}
	bumps := make([]*transaction.MerklePath, len(blocks))
	changed := len(order) != len(raw.BUMPs)
	yes := true // one flag for every node, as Beef.Bytes and NewMerklePathFromReader only read it
	for j, b := range blocks {
		var err error
		if bumps[j], err = b.path(&yes); err != nil {
			return nil, false, err
		}
		changed = changed || b.sources > 1 || b.first != j || !bytes.Equal(bumps[j].Bytes(), raw.BUMPs[b.first].Bytes())
	}
	for i, txids := range named {
		for _, id := range txids {
			e := kept[*id]
			e.BumpIndex = index[i]
			e.Transaction.MerklePath = bumps[index[i]]
		}
	}
	return bumps, changed, nil
}

// block gathers the canonical BUMP of one block: every node each kept txid's
// proof reads, repeats included until path sorts them out.
type block struct {
	n       int // its index among the canonical BUMPs
	first   int // the raw index of its first BUMP
	sources int // the raw BUMPs it gathers
	height  uint32
	root    *chainhash.Hash
	levels  int
	nodes   []node
}

// node is one node a kept txid's proof reads, at level h, flagged when it is
// a kept txid.
type node struct {
	h    int
	el   *transaction.PathElement
	txid bool
}

func newBlock(n, first int, height uint32, root *chainhash.Hash, levels int) *block {
	return &block{n: n, first: first, sources: 1, height: height, root: root, levels: levels}
}

// add records each of txids, which ext proves, and its sibling at every
// level. A path of one level holding one leaf proves the only transaction of
// its block, which is the root, and reads no sibling (ComputeRoot,
// merklepath.go:363-377, which canonicalize has run on ext, refuses that
// leaf at any offset but 0).
func (b *block) add(ext *transaction.MerklePath, txids []*chainhash.Hash) error {
	t := newTree(ext)
	alone := len(ext.Path) == 1 && len(ext.Path[0]) == 1
	for _, id := range txids {
		o, ok := t.offsets[*id]
		if !ok { // Extract places every txid it is given at level 0
			return fmt.Errorf("%w: the proof of %s in block %d does not hold it", ErrRefused, id, b.height)
		}
		b.nodes = append(b.nodes, node{0, &transaction.PathElement{Offset: o, Hash: id}, true})
		for h := 0; h < b.levels && !alone; h++ {
			s := (o >> uint(h)) ^ 1 //nolint:gosec // h >= 0
			el := t.node(h, s)
			if el == nil || (!duplicate(el) && el.Hash == nil) {
				return fmt.Errorf("%w: the proof of %s in block %d has no node at level %d, offset %d", ErrRefused, id, b.height, h, s)
			}
			b.nodes = append(b.nodes, node{h, el, false})
		}
	}
	return nil
}

// path is b as a MerklePath: one copy of each node, holding its hash or its
// duplicate mark and flagged as a txid when any record of it is, each level
// sorted by offset. Records of one node must agree.
func (b *block) path(yes *bool) (*transaction.MerklePath, error) {
	slices.SortFunc(b.nodes, func(x, y node) int { return cmp.Or(cmp.Compare(x.h, y.h), cmp.Compare(x.el.Offset, y.el.Offset)) })
	levels := make([][]*transaction.PathElement, b.levels)
	for i := 0; i < len(b.nodes); {
		first, txid := b.nodes[i], false
		j := i
		for ; j < len(b.nodes) && b.nodes[j].h == first.h && b.nodes[j].el.Offset == first.el.Offset; j++ {
			el := b.nodes[j].el
			if duplicate(el) != duplicate(first.el) || (!duplicate(el) && !el.Hash.IsEqual(first.el.Hash)) {
				return nil, fmt.Errorf("%w: proofs of block %d disagree at level %d, offset %d", ErrRefused, b.height, first.h, first.el.Offset)
			}
			txid = txid || b.nodes[j].txid
		}
		n := &transaction.PathElement{Offset: first.el.Offset}
		if duplicate(first.el) {
			n.Duplicate = yes
		} else {
			hash := *first.el.Hash
			n.Hash = &hash
		}
		if txid {
			n.Txid = yes
		}
		levels[first.h] = append(levels[first.h], n)
		i = j
	}
	b.nodes = nil
	return transaction.NewMerklePath(b.height, levels), nil
}

func duplicate(el *transaction.PathElement) bool { return el.Duplicate != nil && *el.Duplicate }

// tree reads the nodes of a path from Extract as go-sdk v1.7.7's ComputeRoot
// does (getOffsetLeaf and IndexedPath.GetOffsetLeaf, merklepath.go:35-122):
// a node the path holds, the last at its offset winning, or else one computed
// from its children, the right one a duplicate mark meaning the left again.
// It does not need their rule for a single-level path's unpaired last node:
// Extract's path has every level its tree has, and a path of one level is
// only ever read at level 0. Computed nodes are kept, so each is hashed once
// for all the txids that read it.
type tree struct {
	index []map[uint64]*transaction.PathElement
	// offsets holds each txid-flagged level-0 hash's offset: the first leaf
	// holding it, which ComputeRoot climbs from (merklepath.go:380-386).
	offsets map[chainhash.Hash]uint64
	memo    map[[2]uint64]*transaction.PathElement
}

func newTree(p *transaction.MerklePath) *tree {
	t := &tree{index: make([]map[uint64]*transaction.PathElement, len(p.Path)), offsets: map[chainhash.Hash]uint64{}, memo: map[[2]uint64]*transaction.PathElement{}}
	for h, level := range p.Path {
		t.index[h] = make(map[uint64]*transaction.PathElement, len(level))
		for _, el := range level {
			t.index[h][el.Offset] = el
			if h != 0 || el.Hash == nil || el.Txid == nil || !*el.Txid {
				continue
			}
			if _, ok := t.offsets[*el.Hash]; !ok {
				t.offsets[*el.Hash] = el.Offset
			}
		}
	}
	return t
}

// node is the node at (h, o), or nil if the path neither holds it nor holds
// what it is computed from.
func (t *tree) node(h int, o uint64) *transaction.PathElement {
	if h < len(t.index) {
		if el, ok := t.index[h][o]; ok {
			return el
		}
	}
	if h == 0 {
		return nil
	}
	k := [2]uint64{uint64(h), o} //nolint:gosec // h > 0
	if el, ok := t.memo[k]; ok {
		return el
	}
	var el *transaction.PathElement
	if left := t.node(h-1, 2*o); left != nil && left.Hash != nil {
		switch right := t.node(h-1, 2*o+1); {
		case right != nil && right.Hash != nil:
			el = &transaction.PathElement{Offset: o, Hash: transaction.MerkleTreeParent(left.Hash, right.Hash)}
		case right != nil && duplicate(right):
			el = &transaction.PathElement{Offset: o, Hash: transaction.MerkleTreeParent(left.Hash, left.Hash)}
		}
	}
	t.memo[k] = el
	return el
}
