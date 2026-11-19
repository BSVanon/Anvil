// Package beefnormtest builds BEEFs with real proofs for tests of the routes
// that normalize untrusted BEEFs: transactions spending OP_TRUE outputs,
// blocks of any height holding them at chosen offsets, a chain tracker that
// knows those blocks' roots, and encoders that write any set of entries, the
// unrelated ones ts-sdk 2.1.0 leaves in an Atomic BEEF included.
//
// It is test support: import it only from _test.go files, never from
// production code.
package beefnormtest

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Lock is the OP_TRUE locking script every output pays; an empty unlocking
// script spends it.
func Lock() *script.Script { return &script.Script{script.OpTRUE} }

// Parent returns a distinct transaction, for each seed, paying n OP_TRUE
// outputs of sats each. Its one input spends a non-null outpoint no BEEF
// carries, so it is spendable only once proven mined.
func Parent(seed uint64, n int, sats uint64) *transaction.Transaction {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	prev := chainhash.DoubleHashH(append([]byte("beefnormtest parent"), b[:]...))
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID: &prev, UnlockingScript: &script.Script{}, SequenceNumber: transaction.DefaultSequenceNumber,
	})
	for i := 0; i < n; i++ {
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: Lock(), Satoshis: sats})
	}
	return tx
}

// Spend returns a transaction spending output 0 of each source with an empty
// unlocking script and paying one OP_TRUE output of 1 satoshi.
func Spend(sources ...*transaction.Transaction) *transaction.Transaction {
	tx := transaction.NewTransaction()
	for _, src := range sources {
		tx.AddInputFromTx(src, 0, nil)
		tx.Inputs[len(tx.Inputs)-1].UnlockingScript = &script.Script{}
	}
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: Lock(), Satoshis: 1})
	return tx
}

type key struct {
	h int
	o uint64
}

// Block is a block at height Number whose merkle tree has Levels levels,
// holding chosen txids at chosen offsets. Every other leaf is pseudo-random,
// and every node on a chosen txid's path is the hash of its children, so
// every proof Block gives has one root. A block from NewBlock makes every
// node off those paths pseudo-random too, so a proof costs its own size even
// in a tall tree; a block from NewFullBlock hashes every node from its
// children, as Flat needs.
type Block struct {
	Number uint32
	Levels int

	txids   []*chainhash.Hash
	offsets []uint64
	full    bool
	owner   map[key]bool
	memo    map[key]*chainhash.Hash
}

// NewBlock is a block of 2^levels transactions at height number holding
// txids[i] at offsets[i].
func NewBlock(number uint32, levels int, txids []*chainhash.Hash, offsets []uint64) *Block {
	return newBlock(number, levels, txids, offsets, false)
}

// NewFullBlock is NewBlock with every node the hash of its children.
func NewFullBlock(number uint32, levels int, txids []*chainhash.Hash, offsets []uint64) *Block {
	return newBlock(number, levels, txids, offsets, true)
}

func newBlock(number uint32, levels int, txids []*chainhash.Hash, offsets []uint64, full bool) *Block {
	b := &Block{Number: number, Levels: levels, txids: txids, offsets: offsets, full: full, owner: map[key]bool{}, memo: map[key]*chainhash.Hash{}}
	for i, o := range offsets {
		b.memo[key{0, o}] = txids[i]
		for h := 0; h <= levels; h++ {
			b.owner[key{h, o >> h}] = true
		}
	}
	return b
}

// node is the hash at (h, o).
func (b *Block) node(h int, o uint64) *chainhash.Hash {
	k := key{h, o}
	if v, ok := b.memo[k]; ok {
		return v
	}
	var v *chainhash.Hash
	if h > 0 && (b.full || b.owner[k]) {
		v = transaction.MerkleTreeParent(b.node(h-1, 2*o), b.node(h-1, 2*o+1))
	} else {
		var seed [20]byte
		binary.LittleEndian.PutUint32(seed[:], b.Number)
		binary.LittleEndian.PutUint64(seed[4:], uint64(h)) //nolint:gosec // h >= 0
		binary.LittleEndian.PutUint64(seed[12:], o)
		x := chainhash.Hash(sha256.Sum256(seed[:]))
		v = &x
	}
	b.memo[k] = v
	return v
}

// Root is the block's merkle root.
func (b *Block) Root() *chainhash.Hash { return b.node(b.Levels, 0) }

// Proof is the BRC-74 proof of txids[i] alone: it and its sibling at level 0,
// then one sibling per level.
func (b *Block) Proof(i int) *transaction.MerklePath {
	return b.Compound(i)
}

// Compound is one path proving each listed txid, as ts-sdk's trim leaves a
// combined path: every listed txid flagged at level 0, and at each level the
// siblings that cannot be computed from what is kept below.
func (b *Block) Compound(idx ...int) *transaction.MerklePath {
	isTxid := true
	path := make([][]*transaction.PathElement, b.Levels)
	have := map[key]bool{}
	for _, i := range idx {
		have[key{0, b.offsets[i]}] = true
	}
	// computed reports whether the node at (h, o) follows from what is kept.
	var computed func(h int, o uint64) bool
	computed = func(h int, o uint64) bool {
		if have[key{h, o}] {
			return true
		}
		return h > 0 && computed(h-1, 2*o) && computed(h-1, 2*o+1)
	}
	for _, i := range idx {
		path[0] = append(path[0], &transaction.PathElement{Offset: b.offsets[i], Hash: b.txids[i], Txid: &isTxid})
	}
	for h := 0; h < b.Levels; h++ {
		for _, i := range idx {
			sib := (b.offsets[i] >> h) ^ 1
			if computed(h, sib) {
				continue
			}
			have[key{h, sib}] = true
			path[h] = append(path[h], &transaction.PathElement{Offset: sib, Hash: b.node(h, sib)})
		}
		slices.SortFunc(path[h], func(x, y *transaction.PathElement) int { return cmp.Compare(x.Offset, y.Offset) })
	}
	return transaction.NewMerklePath(b.Number, path)
}

// Flat is the single-level compound path holding every leaf of the block at
// level 0, the chosen txids flagged, which go-sdk and ts-sdk accept: its root
// is computed over as many levels as its widest offset needs. It is for small
// blocks from NewFullBlock: it holds 2^Levels leaves, and their root is the
// block's only when every node is hashed from its children.
func (b *Block) Flat() *transaction.MerklePath {
	if !b.full {
		panic("beefnormtest: Flat needs a block from NewFullBlock")
	}
	isTxid := true
	chosen := map[uint64]bool{}
	for _, o := range b.offsets {
		chosen[o] = true
	}
	level := make([]*transaction.PathElement, 0, 1<<b.Levels)
	for o := uint64(0); o < 1<<b.Levels; o++ {
		el := &transaction.PathElement{Offset: o, Hash: b.node(0, o)}
		if chosen[o] {
			el.Txid = &isTxid
		}
		level = append(level, el)
	}
	return transaction.NewMerklePath(b.Number, [][]*transaction.PathElement{level})
}

// Consolidation is k parents mined in one block of 2^levels transactions at
// height number, at offsets spread evenly over the whole block, all proven by
// one compound path as an honest wallet sends them (ts-sdk's Beef.mergeBump
// combines and trims the proofs of one block), and a subject spending output
// 0 of each. k must be at most 2^levels.
func Consolidation(k, levels int, number uint32) (subject *transaction.Transaction, parents []*transaction.Transaction, blk *Block) {
	txids := make([]*chainhash.Hash, k)
	offsets := make([]uint64, k)
	idx := make([]int, k)
	for i := 0; i < k; i++ {
		p := Parent(uint64(number)<<32|uint64(i), 1, 1000) //nolint:gosec // i < 2^32
		parents = append(parents, p)
		txids[i] = p.TxID()
		offsets[i] = uint64(i) * (uint64(1) << levels / uint64(k)) //nolint:gosec // i, k > 0
		idx[i] = i
	}
	blk = NewBlock(number, levels, txids, offsets)
	path := blk.Compound(idx...)
	for _, p := range parents {
		p.MerklePath = path
	}
	return Spend(parents...), parents, blk
}

// Tracker is a chain tracker that knows the roots of the blocks added to it.
type Tracker map[uint32]*chainhash.Hash

// Add records each block's root.
func (t Tracker) Add(blocks ...*Block) Tracker {
	for _, b := range blocks {
		t[b.Number] = b.Root()
	}
	return t
}

// IsValidRootForHeight reports whether root is the root recorded at height.
func (t Tracker) IsValidRootForHeight(_ context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	want, ok := t[height]
	return ok && want.IsEqual(root), nil
}

// CurrentHeight is a tip above every block a test uses.
func (Tracker) CurrentHeight(context.Context) (uint32, error) { return 2_000_000, nil }

// Encode writes a BEEF of version transaction.BEEF_V1 or BEEF_V2 holding
// bumps and an entry for each of txs, with subject last: an entry with a
// BUMP index for a transaction whose MerklePath is one of bumps, and a raw
// entry otherwise. Entries are written parents first, the rest in no
// particular order, as Beef.Bytes writes them.
func Encode(t testing.TB, version uint32, subject *transaction.Transaction, bumps []*transaction.MerklePath, txs ...*transaction.Transaction) []byte {
	t.Helper()
	b := &transaction.Beef{Version: version, BUMPs: bumps, Transactions: map[chainhash.Hash]*transaction.BeefTx{}, NewestTxID: subject.TxID()}
	for _, tx := range append(txs, subject) {
		e := &transaction.BeefTx{DataFormat: transaction.RawTx, Transaction: tx}
		for i, p := range bumps {
			if tx.MerklePath == p {
				e.DataFormat, e.BumpIndex = transaction.RawTxAndBumpIndex, i
			}
		}
		b.Transactions[*tx.TxID()] = e
	}
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("beefnormtest: encode: %v", err)
	}
	return out
}

// Atomic wraps a BEEF for subject in an Atomic BEEF's header, unchecked, as
// ts-sdk's toBinaryAtomic does.
func Atomic(subject *transaction.Transaction, inner []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, transaction.ATOMIC_BEEF)
	out = append(out, subject.TxID()[:]...)
	return append(out, inner...)
}
