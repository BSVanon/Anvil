package beefscan

import (
	"encoding/binary"
	"math/bits"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// maxTrackedBUMPs is how many BUMPs a walk groups by block height. Further
// BUMPs are counted, but their heights are not kept, and ProofCost then falls
// back to treating every BUMP as one height of the tallest path a BUMP can
// declare, which can only overstate it. Each tracked BUMP costs 16 bytes and
// the table's capacity never passes this, so it never passes 1 MiB; it
// doubles only as BUMPs are actually read, each at least 3 bytes of input. Any
// BUMPs cap at or below this keeps the costs exact for every BEEF that cap
// admits; Default's is far below it.
const maxTrackedBUMPs = 1 << 16

// bumpStat is what one BUMP adds to the per-height costs.
type bumpStat struct {
	height uint32 // the parser keeps only the low 32 bits of the height varint
	levels byte   // the tree height it declares
	need   byte   // the levels its widest level-0 offset needs: bits.Len64
	refs   uint64 // transaction entries that name this BUMP by index
}

// walker reads b the way go-sdk v1.7.7's BEEF entry points read it
// (NewBeefFromBytes, NewBeefFromAtomicBytes, ParseBeef and
// NewTransactionFromBEEF all read the same V1 or V2 layout, behind an optional
// Atomic prefix), counting what it finds. It is adapted from peerhygiene's
// costWalker. It checks nothing the parser does not: where b is malformed the
// walk stops at the first byte the layout cannot account for, which is never
// before the point where the parser fails, so the counts cover everything the
// parser can have read. A count the parser checks against the bytes left (at
// least so many bytes per element) is checked the same way here.
//
// With limited set, the walk stops as soon as a count passes its cap in caps,
// and over names that cap.
type walker struct {
	b       []byte
	pos     int
	shape   Shape
	limited bool
	caps    Limits
	over    *exceeded

	bumps    []bumpStat // the first maxTrackedBUMPs BUMPs, in order
	refs     uint64     // BUMP index references, tracked or not
	unproven uint64     // entries carrying a transaction but no BUMP index
	txidOnly uint64
}

// exceeded names the first cap a walk found passed.
type exceeded struct {
	name       string
	value, cap uint64
}

func (w *walker) left() uint64 { return uint64(len(w.b) - w.pos) } //nolint:gosec // pos never passes len(b)

func (w *walker) skip(n uint64) bool {
	if n > w.left() {
		return false
	}
	w.pos += int(n) //nolint:gosec // bounded by left() just above
	return true
}

func (w *walker) byte1() (byte, bool) {
	if w.left() < 1 {
		return 0, false
	}
	w.pos++
	return w.b[w.pos-1], true
}

// varint reads a CompactSize integer, non-minimal encodings included, as
// go-sdk does.
func (w *walker) varint() (uint64, bool) {
	p, ok := w.byte1()
	if !ok {
		return 0, false
	}
	var size uint64
	switch p {
	case 0xfd:
		size = 2
	case 0xfe:
		size = 4
	case 0xff:
		size = 8
	default:
		return uint64(p), true
	}
	if w.left() < size {
		return 0, false
	}
	var v uint64
	for i := uint64(0); i < size; i++ {
		v |= uint64(w.b[w.pos]) << (8 * i)
		w.pos++
	}
	return v, true
}

// count reads a declared element count, refusing it as the parser does when
// fewer than minBytes bytes per element are left.
func (w *walker) count(minBytes uint64) (uint64, bool) {
	n, ok := w.varint()
	if !ok || n > w.left()/minBytes {
		return 0, false
	}
	return n, true
}

// add bumps one of the shape's counts and reports whether the walk may go on.
func (w *walker) add(n *int, cap int, name string) bool {
	*n++
	if w.limited && *n > cap {
		w.over = &exceeded{name: name, value: uint64(*n), cap: uint64(cap)} //nolint:gosec // counts and caps are positive
		return false
	}
	return true
}

// script skips a length-prefixed script.
func (w *walker) script() bool {
	n, ok := w.varint()
	return ok && w.skip(n)
}

// walk reads the whole BEEF, then derives the per-height costs.
func (w *walker) walk() {
	if len(w.b) >= 4 && binary.LittleEndian.Uint32(w.b) == transaction.ATOMIC_BEEF {
		w.shape.Atomic = true
		if len(w.b) < 36 {
			return
		}
		w.pos = 36
	}
	if w.left() < 4 {
		return
	}
	version := binary.LittleEndian.Uint32(w.b[w.pos:])
	if version != transaction.BEEF_V1 && version != transaction.BEEF_V2 {
		return
	}
	w.pos += 4
	w.shape.Version = version
	if w.readBUMPs() {
		w.readTxs(version == transaction.BEEF_V2)
	}
	if w.over == nil {
		w.costs()
	}
}

func (w *walker) readBUMPs() bool {
	n, ok := w.count(2)
	for i := uint64(0); ok && i < n; i++ {
		ok = w.readBUMP()
	}
	return ok
}

func (w *walker) readBUMP() bool {
	if !w.add(&w.shape.BUMPs, w.caps.BUMPs, "BUMPs") {
		return false
	}
	height, ok := w.varint()
	if !ok {
		return false
	}
	var stat bumpStat
	stat.height = uint32(height) //nolint:gosec // the parser truncates the same way
	tree, ok := w.byte1()
	stat.levels = tree
	for lv := byte(0); ok && lv < tree; lv++ {
		var n uint64
		n, ok = w.count(2)
		for i := uint64(0); ok && i < n; i++ {
			var offset uint64
			var flags byte
			if offset, ok = w.varint(); ok {
				flags, ok = w.byte1()
			}
			if !ok {
				break
			}
			if lv == 0 {
				stat.need = max(stat.need, byte(bits.Len64(offset))) //nolint:gosec // at most 64
			}
			// The parser holds the leaf before it reads the hash.
			if ok = w.add(&w.shape.Leaves, w.caps.Leaves, "leaves"); !ok {
				break
			}
			if flags&1 == 0 {
				ok = w.skip(32)
			}
		}
	}
	if n := len(w.bumps); n < maxTrackedBUMPs {
		if n == cap(w.bumps) { // double, but never past maxTrackedBUMPs
			grown := make([]bumpStat, n, min(max(2*n, 16), maxTrackedBUMPs))
			copy(grown, w.bumps)
			w.bumps = grown
		}
		w.bumps = append(w.bumps, stat)
	}
	return ok
}

// ref records an entry naming BUMP index i, which the parser refuses unless a
// BUMP with that index was read.
func (w *walker) ref(i uint64) bool {
	if i >= uint64(w.shape.BUMPs) { //nolint:gosec // BUMPs is a count
		return false
	}
	w.refs++
	if i < uint64(len(w.bumps)) {
		w.bumps[i].refs++
	}
	return true
}

func (w *walker) readTxs(v2 bool) {
	minEntry := uint64(10)
	if v2 {
		minEntry = 11
	}
	n, ok := w.count(minEntry)
	for i := uint64(0); ok && i < n; i++ {
		if !w.add(&w.shape.Txs, w.caps.Txs, "transactions") {
			return
		}
		if v2 {
			format, okf := w.byte1()
			switch {
			case !okf || format > 2:
				return
			case format == 2: // txid only
				w.txidOnly++
				ok = w.skip(32)
				continue
			case format == 1: // BUMP index, then the transaction
				var idx uint64
				if idx, ok = w.varint(); !ok || !w.ref(idx) {
					return
				}
			default:
				w.unproven++
			}
		}
		ok = w.readTx()
		if ok && !v2 {
			var hasBump byte
			if hasBump, ok = w.byte1(); !ok || hasBump > 1 {
				return
			}
			if hasBump == 0 {
				w.unproven++
				continue
			}
			var idx uint64
			if idx, ok = w.varint(); ok {
				ok = w.ref(idx)
			}
		}
	}
}

// readTx walks one transaction as Transaction.ReadFrom reads it, extended
// format included.
func (w *walker) readTx() bool {
	if !w.skip(4) { // version
		return false
	}
	nIn, ok := w.varint()
	if !ok {
		return false
	}
	extended := false
	var nOut uint64
	if nIn == 0 {
		if nOut, ok = w.varint(); !ok {
			return false
		}
		if nOut == 0 {
			if w.left() < 4 {
				return false
			}
			marker := binary.BigEndian.Uint32(w.b[w.pos:])
			w.pos += 4
			if marker != 0xEF { // an empty transaction: that was its lock time
				return true
			}
			extended = true
			if nIn, ok = w.varint(); !ok {
				return false
			}
		}
	}
	if nIn > w.left()/41 {
		return false
	}
	for i := uint64(0); i < nIn; i++ {
		if !w.add(&w.shape.Inputs, w.caps.Inputs, "inputs") {
			return false
		}
		if !w.skip(36) || !w.script() || !w.skip(4) {
			return false
		}
		if extended && (!w.skip(8) || !w.script()) { // the source output
			return false
		}
	}
	if nIn > 0 || extended {
		if nOut, ok = w.varint(); !ok {
			return false
		}
	}
	if nOut > w.left()/9 {
		return false
	}
	for i := uint64(0); i < nOut; i++ {
		if !w.add(&w.shape.Outputs, w.caps.Outputs, "outputs") {
			return false
		}
		if !w.skip(8) || !w.script() {
			return false
		}
	}
	return w.skip(4) // lock time
}
