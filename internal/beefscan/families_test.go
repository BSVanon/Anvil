package beefscan

import (
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// The shape families the cap tests and the calibration share. Each takes the
// value of the dimension it stresses and returns the worst BEEF found for that
// value that stays inside every other cap, so one past a cap trips that cap
// alone.

// block is the height of every single-height shape.
const block = 900000

// combineLeaves is the width of combineShape's shared BUMP. At the combine
// cap, widths from 4,097 to 32,769 leaves all took 0.63 to 0.69 s to parse as
// V1; at 16,385 leaves every level has an unpaired node, which ComputeRoot
// fills with a duplicate.
const combineLeaves = 16385

// findBUMPs is how many BUMPs findShape's proof search asks about each
// unproven transaction at the find cap: the BUMPs cap.
const findBUMPs = 10000

// spent is a proven parent with one output, and its 21-leaf proof.
func spent() (raw []byte, id [32]byte, proof []byte) {
	raw = rawTx(2, nil, []int{0})
	id = sha256d(raw)
	return raw, id, proofBUMP(block, 20, 4000, id, 1)
}

// spender is a subject spending output 0 of the transaction id.
func spender(id [32]byte) entry {
	return entry{raw: rawTx(1, []outpoint{{txid: id}}, []int{0}), bump: -1}
}

// txsShape is n entries, n-1 bare txids and one empty transaction, which only
// the transactions cap limits. It is V2: V1 has no txid-only entries.
func txsShape(n int) []byte {
	es := make([]entry, 0, n)
	for i := 0; i < n-1; i++ {
		id := node(11, uint64(i))
		es = append(es, entry{txidOnly: &id})
	}
	return beefBytes(true, nil, append(es, entry{raw: emptyTx(1), bump: -1}))
}

// emptyTxs is n unproven empty transactions. At the transactions cap it is at
// the chain cost cap too: 10,000 * 10,000.
func emptyTxs(v2 bool, n int) []byte {
	es := make([]entry, n)
	for i := range es {
		es[i] = entry{raw: emptyTx(uint32(i) + 1), bump: -1}
	}
	return beefBytes(v2, nil, es)
}

// inputsShape is a proven parent and a subject with n inputs, all spending
// the parent's output.
func inputsShape(v2 bool, n int) []byte {
	raw, id, proof := spent()
	ins := make([]outpoint, n)
	for i := range ins {
		ins[i] = outpoint{txid: id}
	}
	return beefBytes(v2, [][]byte{proof}, []entry{{raw: raw, bump: 0}, {raw: rawTx(1, ins, []int{0}), bump: -1}})
}

// outputsShape is one transaction of n empty outputs.
func outputsShape(v2 bool, n int) []byte {
	return beefBytes(v2, nil, []entry{{raw: rawTx(1, nil, make([]int, n)), bump: -1}})
}

// bumpsShape is n 19-leaf proofs at distinct heights, the first proving a
// parent that a subject spends. MergeBeef scans every BUMP merged so far for
// each one it merges.
func bumpsShape(v2 bool, n int) []byte {
	raw, id, _ := spent()
	bumps := make([][]byte, n)
	for i := range bumps {
		txid := node(12, uint64(i))
		if i == 0 {
			txid = id
		}
		bumps[i] = proofBUMP(uint64(i)+1, 18, 4000, txid, uint64(i))
	}
	return beefBytes(v2, bumps, []entry{{raw: raw, bump: 0}, spender(id)})
}

// leavesShape is one one-level BUMP of n hashed leaves, the first proving a
// parent that a subject spends, so Verify computes one root over all n.
func leavesShape(v2 bool, n int) []byte {
	raw, id, _ := spent()
	level := make([]leaf, n)
	for i := range level {
		level[i] = leaf{offset: uint64(i), hash: node(13, uint64(i))}
	}
	level[0] = leaf{offset: 0, flags: 2, hash: id}
	return beefBytes(v2, [][]byte{bump(block, [][]leaf{level})}, []entry{{raw: raw, bump: 0}, spender(id)})
}

// combineShape is k parents sharing one one-level BUMP of combineLeaves
// leaves, and a subject spending them all: combine cost (k+1)*combineLeaves.
func combineShape(v2 bool, k int) []byte {
	entries, _ := fanIn(k, func(int) int { return 0 })
	return beefBytes(v2, [][]byte{compoundBUMP(block, combineLeaves, 0, 1)}, entries)
}

// rootShape is a one-level BUMP of n leaves, each flagged as a txid, that a
// parent names: Verify computes n roots, each over n leaves.
func rootShape(v2 bool, n int) []byte {
	entries, _ := fanIn(1, func(int) int { return 0 })
	return beefBytes(v2, [][]byte{compoundBUMP(block, n, 2, 1)}, entries)
}

// chainShape is a chain of n unproven transactions from a root whose BUMP
// does not prove it, each spending the one before it and, extra times, the
// root: Verify's validation passes walk every input still waiting.
func chainShape(v2 bool, n, extra int) []byte {
	entries, _ := chain(n, extra)
	return beefBytes(v2, [][]byte{proofBUMP(block, 20, 4000, node(9, 9), 1)}, entries)
}

// findShape is an Atomic BEEF of a chain of u unproven transactions from a
// proven root, and b two-leaf BUMPs at distinct heights: NewTransactionFromBEEF
// asks every BUMP whether it proves each unproven transaction.
func findShape(u, b int) []byte {
	bumps := make([][]byte, b)
	for i := range bumps {
		n := 2 * uint64(i)
		bumps[i] = bump(uint64(i)+1, [][]leaf{{{0, 0, node(14, n)}, {1, 0, node(14, n+1)}}})
	}
	entries, subject := chain(u, 0)
	return atomicBEEF(subject, beefBytes(true, bumps, entries))
}

// sameBlockFanIn is the red-team review's shape: k parents, each with its own proof in one
// block, and a subject spending them all. Combining them grows one path by
// every proof in turn.
func sameBlockFanIn(v2 bool, k int) []byte {
	txids := make([][32]byte, k)
	offsets := make([]uint64, k)
	ins := make([]outpoint, k)
	entries := make([]entry, 0, k+1)
	for i := range txids {
		raw := rawTx(uint32(i)+2, nil, []int{0})
		txids[i] = sha256d(raw)
		offsets[i] = uint64(i) * 1048573 % (1 << 20)
		ins[i] = outpoint{txid: txids[i]}
		entries = append(entries, entry{raw: raw, bump: i})
	}
	entries = append(entries, entry{raw: rawTx(1, ins, []int{0}), bump: -1})
	return beefBytes(v2, sameBlock(block, 20, txids, offsets, k), entries)
}

// sameBlockBUMPs is b proofs of one block, only the first naming an entry: a
// proven parent that a subject spends. MergeBeef merges each of the other
// proofs into the first, growing one path by every proof in turn.
func sameBlockBUMPs(b int) []byte {
	raw, id, _ := spent()
	txids := make([][32]byte, b)
	offsets := make([]uint64, b)
	for i := range txids {
		txids[i] = node(15, uint64(i))
		offsets[i] = uint64(i) * 1048573 % (1 << 20)
	}
	txids[0] = id
	return beefBytes(true, sameBlock(block, 20, txids, offsets, 1), []entry{{raw: raw, bump: 0}, spender(id)})
}

// tallPathFanIn is k parents sharing one 255-level path of duplicate nodes,
// the tallest a BUMP can declare, and a subject spending them all.
func tallPathFanIn(k int) []byte {
	levels := make([][]leaf, 255)
	levels[0] = []leaf{{offset: 0, flags: 2, hash: node(1, 1)}, {offset: 1, flags: 1}}
	for h := 1; h < 255; h++ {
		levels[h] = []leaf{{offset: 1, flags: 1}}
	}
	entries, _ := fanIn(k, func(int) int { return 0 })
	return beefBytes(false, [][]byte{bump(block, levels)}, entries)
}

// huge writes a V2 BEEF of about size bytes: head, a count, as many
// elements from elem as fit, then tail. It builds into one buffer, so a
// 64 MiB shape costs one allocation.
func huge(size int, head []byte, elemSize int, elem func(b []byte, i int) []byte, tail []byte) []byte {
	n := (size - 4 - len(head) - 9 - len(tail)) / elemSize
	b := binary.LittleEndian.AppendUint32(make([]byte, 0, size), transaction.BEEF_V2)
	b = append(append(b, head...), util.VarInt(uint64(n)).Bytes()...) //nolint:gosec // n is positive
	for i := 0; i < n; i++ {
		b = elem(b, i)
	}
	return append(b, tail...)
}

// oneEmptyTx is a transaction list of one unproven empty transaction.
var oneEmptyTx = append([]byte{1, 0}, emptyTx(1)...)

// The reviewer's 64 MiB amplification shapes, each a V2 BEEF of one element
// repeated to fill the body. ParseBeef holds 4.1 to 22 times each element's
// bytes (TestCalibrateHeap, at 4 MiB).

func hugeEmptyTxs(size int) []byte { // 11 bytes each
	return huge(size, []byte{0}, 11, func(b []byte, i int) []byte {
		return append(binary.LittleEndian.AppendUint32(append(b, 0), uint32(i)+1), 0, 0, 0, 0, 0, 0) //nolint:gosec // i < 2^32
	}, nil)
}

func hugeTxids(size int) []byte { // 33 bytes each
	return huge(size, []byte{0}, 33, func(b []byte, i int) []byte {
		return append(binary.LittleEndian.AppendUint64(append(b, 2), uint64(i)), make([]byte, 24)...) //nolint:gosec // i >= 0
	}, nil)
}

func hugeDupLeaves(size int) []byte { // 2 bytes each, in one BUMP
	return huge(size, []byte{1, 1, 1}, 2, func(b []byte, _ int) []byte { return append(b, 0, 1) }, oneEmptyTx)
}

func hugeBUMPs(size int) []byte { // 9 bytes each, one duplicate leaf apiece
	return huge(size, nil, 9, func(b []byte, i int) []byte {
		return append(binary.LittleEndian.AppendUint32(append(b, 0xfe), uint32(i)+1), 1, 1, 0, 1) //nolint:gosec // i < 2^32
	}, oneEmptyTx)
}

func hugeOutputs(size int) []byte { // 9 bytes each, in one transaction
	head := binary.LittleEndian.AppendUint32([]byte{0, 1, 0}, 1)
	return huge(size, append(head, 0), 9, func(b []byte, _ int) []byte {
		return append(b, 1, 0, 0, 0, 0, 0, 0, 0, 0)
	}, []byte{0, 0, 0, 0})
}

func hugeInputs(size int) []byte { // 41 bytes each, in one transaction
	head := binary.LittleEndian.AppendUint32([]byte{0, 1, 0}, 1)
	tail := append([]byte{1, 1, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0, 0, 0)
	return huge(size, head, 41, func(b []byte, i int) []byte {
		b = binary.LittleEndian.AppendUint64(b, uint64(i)) //nolint:gosec // i >= 0
		return append(b, make([]byte, 33)...)
	}, tail)
}
