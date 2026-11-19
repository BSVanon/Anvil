package beefscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// This file writes BEEFs byte by byte, so a test can build any shape at any
// size quickly, including shapes no wallet would make.

// sha256d is the double SHA-256 go-sdk uses for txids and merkle nodes.
func sha256d(b []byte) [32]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// node is a pseudo-random 32-byte hash, distinct for each (seed, i).
func node(seed, i uint64) [32]byte {
	var b [16]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	binary.LittleEndian.PutUint64(b[8:], i)
	return sha256.Sum256(b[:])
}

// wire appends BEEF fields.
type wire struct{ bytes.Buffer }

func (w *wire) u32(v uint32)    { _ = binary.Write(w, binary.LittleEndian, v) }
func (w *wire) varint(v uint64) { w.Write(util.VarInt(v).Bytes()) }

// leaf is one BUMP path element as BRC-74 writes it.
type leaf struct {
	offset uint64
	flags  byte // 1: duplicate, no hash; 2: txid
	hash   [32]byte
}

// bump encodes a BUMP: its block height, then each level's leaves.
func bump(height uint64, levels [][]leaf) []byte {
	var w wire
	w.varint(height)
	w.WriteByte(byte(len(levels)))
	for _, level := range levels {
		w.varint(uint64(len(level)))
		for _, l := range level {
			w.varint(l.offset)
			w.WriteByte(l.flags)
			if l.flags&1 == 0 {
				w.Write(l.hash[:])
			}
		}
	}
	return w.Bytes()
}

// proofBUMP is a one-transaction proof: txid and its sibling at level 0, then
// one sibling per level up to a tree of the given height. Its leaves number
// height+1.
func proofBUMP(block uint64, height int, offset uint64, txid [32]byte, seed uint64) []byte {
	levels := make([][]leaf, height)
	self := leaf{offset: offset, flags: 2, hash: txid}
	sib := leaf{offset: offset ^ 1, hash: node(seed, 0)}
	if offset&1 == 0 {
		levels[0] = []leaf{self, sib}
	} else {
		levels[0] = []leaf{sib, self}
	}
	for h := 1; h < height; h++ {
		levels[h] = []leaf{{offset: (offset >> h) ^ 1, hash: node(seed, uint64(h))}}
	}
	return bump(block, levels)
}

// compoundBUMP is a one-level BUMP of n leaves at offsets 0 to n-1, every one
// with a hash, so computing a root from it hashes the whole tree. flags is
// applied to every leaf.
func compoundBUMP(block uint64, n int, flags byte, seed uint64) []byte {
	level := make([]leaf, n)
	for i := range level {
		level[i] = leaf{offset: uint64(i), flags: flags, hash: node(seed, uint64(i))}
	}
	return bump(block, [][]leaf{level})
}

// entry is one BEEF transaction entry: raw bytes with an optional BUMP index,
// or a bare txid.
type entry struct {
	raw      []byte
	bump     int // -1 for none
	txidOnly *[32]byte
}

// beefBytes writes a V1 or V2 BEEF of the given BUMPs and entries.
func beefBytes(v2 bool, bumps [][]byte, entries []entry) []byte {
	var w wire
	if v2 {
		w.u32(transaction.BEEF_V2)
	} else {
		w.u32(transaction.BEEF_V1)
	}
	w.varint(uint64(len(bumps)))
	for _, b := range bumps {
		w.Write(b)
	}
	w.varint(uint64(len(entries)))
	for _, e := range entries {
		switch {
		case e.txidOnly != nil:
			w.WriteByte(2)
			w.Write(e.txidOnly[:])
		case v2 && e.bump >= 0:
			w.WriteByte(1)
			w.varint(uint64(e.bump))
			w.Write(e.raw)
		case v2:
			w.WriteByte(0)
			w.Write(e.raw)
		case e.bump >= 0:
			w.Write(e.raw)
			w.WriteByte(1)
			w.varint(uint64(e.bump))
		default:
			w.Write(e.raw)
			w.WriteByte(0)
		}
	}
	return w.Bytes()
}

// atomicBEEF wraps an inner BEEF for the given subject txid.
func atomicBEEF(subject [32]byte, inner []byte) []byte {
	var w wire
	w.u32(transaction.ATOMIC_BEEF)
	w.Write(subject[:])
	w.Write(inner)
	return w.Bytes()
}

// outpoint is a transaction input's source.
type outpoint struct {
	txid [32]byte
	vout uint32
}

// rawTx writes a transaction: version, the inputs with empty unlocking
// scripts, outputs of the given locking-script sizes, and a zero lock time.
func rawTx(version uint32, ins []outpoint, outScripts []int) []byte {
	var w wire
	w.u32(version)
	w.varint(uint64(len(ins)))
	for _, in := range ins {
		w.Write(in.txid[:])
		w.u32(in.vout)
		w.varint(0)
		w.u32(0xffffffff)
	}
	w.varint(uint64(len(outScripts)))
	for _, n := range outScripts {
		_ = binary.Write(&w, binary.LittleEndian, uint64(1))
		w.varint(uint64(n))
		w.Write(make([]byte, n))
	}
	w.u32(0)
	return w.Bytes()
}

// emptyTx is a distinct ten-byte transaction with no inputs or outputs.
func emptyTx(version uint32) []byte { return rawTx(version, nil, nil) }

// efTx writes an extended-format (BRC-30) transaction: each input carries its
// source output's satoshis and a locking script of sourceScript bytes.
func efTx(ins []outpoint, sourceScript int, outScripts []int) []byte {
	var w wire
	w.u32(1)
	w.Write([]byte{0, 0, 0, 0, 0, 0xEF})
	w.varint(uint64(len(ins)))
	for _, in := range ins {
		w.Write(in.txid[:])
		w.u32(in.vout)
		w.varint(0)
		w.u32(0xffffffff)
		_ = binary.Write(&w, binary.LittleEndian, uint64(1000))
		w.varint(uint64(sourceScript))
		w.Write(make([]byte, sourceScript))
	}
	w.varint(uint64(len(outScripts)))
	for _, n := range outScripts {
		_ = binary.Write(&w, binary.LittleEndian, uint64(1))
		w.varint(uint64(n))
		w.Write(make([]byte, n))
	}
	w.u32(0)
	return w.Bytes()
}

// sameBlock gives each txid its own proof, at the given offsets of one block
// of 2^height transactions, all against the same root: a node off every path
// is pseudo-random and a node on one is the hash of its children. The first
// flagged proofs flag their txid as one.
func sameBlock(block uint64, height int, txids [][32]byte, offsets []uint64, flagged int) [][]byte {
	type key struct {
		h int
		o uint64
	}
	memo := map[key][32]byte{}
	owner := map[key]int{}
	for i, o := range offsets {
		for h := 0; h <= height; h++ {
			owner[key{h, o >> h}] = i + 1
		}
	}
	var get func(h int, o uint64) [32]byte
	get = func(h int, o uint64) [32]byte {
		k := key{h, o}
		if v, ok := memo[k]; ok {
			return v
		}
		var v [32]byte
		switch i, on := owner[k]; {
		case !on:
			v = node(uint64(h)<<40^7, o)
		case h == 0:
			v = txids[i-1]
		default:
			l, r := get(h-1, 2*o), get(h-1, 2*o+1)
			v = sha256d(append(l[:], r[:]...))
		}
		memo[k] = v
		return v
	}
	out := make([][]byte, len(txids))
	for i, o := range offsets {
		levels := make([][]leaf, height)
		self := leaf{offset: o, hash: txids[i]}
		if i < flagged {
			self.flags = 2
		}
		sib := leaf{offset: o ^ 1, hash: get(0, o^1)}
		levels[0] = []leaf{self, sib}
		if o&1 == 1 {
			levels[0] = []leaf{sib, self}
		}
		for h := 1; h < height; h++ {
			levels[h] = []leaf{{offset: (o >> h) ^ 1, hash: get(h, (o>>h)^1)}}
		}
		out[i] = bump(block, levels)
	}
	return out
}

// fanIn is k proven parents, one output each, and a subject that spends them
// all. parentBump(i) gives parent i's BUMP index.
func fanIn(k int, parentBump func(i int) int) (entries []entry, subject [32]byte) {
	ins := make([]outpoint, k)
	for i := 0; i < k; i++ {
		raw := rawTx(uint32(i)+2, nil, []int{0})
		ins[i] = outpoint{txid: sha256d(raw)}
		entries = append(entries, entry{raw: raw, bump: parentBump(i)})
	}
	sub := rawTx(1, ins, []int{0})
	return append(entries, entry{raw: sub, bump: -1}), sha256d(sub)
}

// chain is a proven root and n unproven transactions, each spending the one
// before it through its last input; every transaction but the root also
// spends the root through extra inputs first.
func chain(n, extra int) (entries []entry, subject [32]byte) {
	root := rawTx(2, nil, []int{0})
	prev := sha256d(root)
	rootID := prev
	entries = append(entries, entry{raw: root, bump: 0})
	for i := 0; i < n; i++ {
		ins := make([]outpoint, 0, extra+1)
		for j := 0; j < extra; j++ {
			ins = append(ins, outpoint{txid: rootID})
		}
		ins = append(ins, outpoint{txid: prev})
		raw := rawTx(uint32(i)+3, ins, []int{0})
		prev = sha256d(raw)
		entries = append(entries, entry{raw: raw, bump: -1})
	}
	return entries, prev
}
