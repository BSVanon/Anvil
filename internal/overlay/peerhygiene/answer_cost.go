package peerhygiene

import (
	"encoding/binary"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// What decoding one lookup answer may cost, before anything decodes it.
//
// A byte cap alone does not bound the memory an answer claims, because the
// decoders build far larger structures than the bytes they read. go-sdk
// v1.7.7's BEEF parser keeps some 210 bytes alive for every 11-byte empty
// transaction and 44 for every 2-byte duplicate merkle leaf, about 20 times
// the input, and allocates 55 times it in all. encoding/json, decoding the
// "result" member that LookupAnswer holds as an interface{}, keeps over 300
// bytes for every 7-byte object such as {"":0}. beefCost and jsonCost walk the
// bytes without allocating and price every element at or above what those
// decoders keep alive for it, so an answer can be refused before a decoder
// runs. The prices are upper bounds on the heap each element holds while it is
// decoded, with a fifth or more to spare, also under the race detector, which
// turns off the allocator's packing of tiny objects; the tests in
// answer_cost_test.go measure the decoders against them.
const (
	// beefBaseCost covers the Beef value and its maps' fixed parts.
	beefBaseCost = 512
	// txCost covers a Transaction, its BeefTx entry and its txid in every map
	// the parse entry points build for it: NewBeefFromBytes keeps two in V1,
	// and ParseBeef rebuilds the ancestry into another with
	// NewBeefFromTransaction.
	txCost = 640
	// txidOnlyCost covers a V2 txid-only entry: its BeefTx, txid and map slot.
	txidOnlyCost = 320
	// inputCost covers a TransactionInput and its source txid.
	inputCost = 224
	// outputCost covers a TransactionOutput and its slot.
	outputCost = 48
	// scriptCost covers a script's *script.Script header; its bytes are
	// priced on top, with allocator rounding.
	scriptCost = 32
	// bumpCost covers a MerklePath and its BUMP-index map entry.
	bumpCost = 96
	// levelCost covers one level's slice header and its backing array's
	// rounding.
	levelCost = 32
	// leafCost covers a PathElement, its slot in the level and its flags; a
	// leaf that carries a hash adds hashCost.
	leafCost = 64
	hashCost = 32
	// slotCost covers one pointer of a slice the parser pre-sizes from a
	// declared count.
	slotCost = 8
)

// beefCost walks b the way go-sdk v1.7.7's BEEF entry points read it
// (NewBeefFromBytes, NewBeefFromAtomicBytes, ParseBeef and
// NewTransactionFromBEEF all read the same V1 or V2 layout, behind an optional
// Atomic prefix) and returns an upper bound on the heap one of them holds
// while it parses b. It allocates nothing.
//
// The walk checks nothing the parser does not. Where b is malformed the walk
// stops at the first byte the layout cannot account for, which is never
// before the point where the parser fails, and the bound covers everything
// read up to there. A slice the parser pre-sizes from a declared count is
// priced when the count is read, as the parser allocates it then, but only
// when the count passes the parser's own check against the bytes left.
func beefCost(b []byte) uint64 {
	w := &costWalker{b: b, cost: beefBaseCost}
	if len(b) >= 4 && binary.LittleEndian.Uint32(b) == transaction.ATOMIC_BEEF {
		if len(b) < 36 {
			return w.cost
		}
		w.pos = 36
	}
	version, ok := w.uint32()
	if !ok || (version != transaction.BEEF_V1 && version != transaction.BEEF_V2) {
		return w.cost
	}
	if w.bumps() {
		w.txs(version == transaction.BEEF_V2)
	}
	// TxID serializes a transaction to hash it, and the V1 path hashes each
	// one twice. Each serialization is dropped before the next is made, but
	// two may be live at once.
	return w.cost + 2*w.maxTx
}

type costWalker struct {
	b     []byte
	pos   int
	cost  uint64
	maxTx uint64 // the largest transaction walked, in bytes
}

func (w *costWalker) left() uint64 { return uint64(len(w.b) - w.pos) } //nolint:gosec // pos never passes len(b)

func (w *costWalker) skip(n uint64) bool {
	if n > w.left() {
		return false
	}
	w.pos += int(n) //nolint:gosec // bounded by left() just above
	return true
}

func (w *costWalker) byte1() (byte, bool) {
	if w.left() < 1 {
		return 0, false
	}
	w.pos++
	return w.b[w.pos-1], true
}

func (w *costWalker) uint32() (uint32, bool) {
	if w.left() < 4 {
		return 0, false
	}
	w.pos += 4
	return binary.LittleEndian.Uint32(w.b[w.pos-4:]), true
}

// varint reads a CompactSize integer, non-minimal encodings included, as
// go-sdk does.
func (w *costWalker) varint() (uint64, bool) {
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

// count reads a declared element count and prices the slice the parser sizes
// from it, if the parser's guard (at least minBytes per element left) lets it
// through.
func (w *costWalker) count(minBytes uint64, presized bool) (uint64, bool) {
	n, ok := w.varint()
	if !ok || n > w.left()/minBytes {
		return 0, false
	}
	if presized {
		w.cost += n * slotCost
	}
	return n, true
}

// script prices and skips a length-prefixed script.
func (w *costWalker) script() bool {
	n, ok := w.varint()
	if !ok || n > w.left() {
		return false
	}
	w.cost += scriptCost + n + n/8
	if n > 0 {
		w.cost += 16
	}
	return w.skip(n)
}

func (w *costWalker) bumps() bool {
	n, ok := w.count(2, true)
	for i := uint64(0); ok && i < n; i++ {
		ok = w.bump()
	}
	return ok
}

func (w *costWalker) bump() bool {
	w.cost += bumpCost
	if _, ok := w.varint(); !ok { // block height
		return false
	}
	height, ok := w.byte1()
	if !ok {
		return false
	}
	w.cost += uint64(height) * levelCost
	for lv := byte(0); lv < height; lv++ {
		n, ok := w.count(2, true)
		for i := uint64(0); ok && i < n; i++ {
			var flags byte
			if _, ok = w.varint(); ok { // offset
				flags, ok = w.byte1()
			}
			if !ok {
				break
			}
			w.cost += leafCost
			if flags&1 == 0 {
				w.cost += hashCost
				ok = w.skip(32)
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (w *costWalker) txs(v2 bool) {
	minEntry := uint64(10)
	if v2 {
		minEntry = 11
	}
	n, ok := w.count(minEntry, false)
	for i := uint64(0); ok && i < n; i++ {
		if v2 {
			format, okf := w.byte1()
			switch {
			case !okf || format > 2:
				return
			case format == 2: // txid only
				w.cost += txidOnlyCost
				ok = w.skip(32)
				continue
			case format == 1: // bump index, then the transaction
				if _, ok = w.varint(); !ok {
					return
				}
			}
		}
		start := w.pos
		w.cost += txCost
		ok = w.tx()
		if size := uint64(w.pos - start); size > w.maxTx { //nolint:gosec // pos only grows
			w.maxTx = size
		}
		if ok && !v2 {
			var hasBump byte
			if hasBump, ok = w.byte1(); ok && hasBump == 1 {
				_, ok = w.varint()
			}
			ok = ok && hasBump <= 1
		}
	}
}

// tx walks one transaction as Transaction.ReadFrom reads it, extended format
// included.
func (w *costWalker) tx() bool {
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
	w.cost += nIn * slotCost
	for i := uint64(0); i < nIn; i++ {
		w.cost += inputCost
		if !w.skip(36) || !w.script() || !w.skip(4) {
			return false
		}
		if extended { // the source output's satoshis and locking script
			w.cost += outputCost
			if !w.skip(8) || !w.script() {
				return false
			}
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
	w.cost += nOut * slotCost
	for i := uint64(0); i < nOut; i++ {
		w.cost += outputCost
		if !w.skip(8) || !w.script() {
			return false
		}
	}
	return w.skip(4) // lock time
}

// JSON prices: an object decoded into a map[string]any (its header and first
// group of slots), an array's boxed slice header and first element, every
// further member or element (its slot, a boxed scalar, and growth), and every
// string's boxed header with its bytes and allocator rounding.
const (
	jsonBaseCost   = 4096
	jsonObjectCost = 512
	jsonArrayCost  = 128
	jsonSepCost    = 80
	jsonStringCost = 48
)

// jsonCost returns an upper bound on the heap encoding/json holds while it
// unmarshals b into a lookup.LookupAnswer. Every value is priced as if it were
// decoded into an interface{}, which no value costs less than: the answer's
// "result" member is one, and outputs decode into fixed structs. Separators
// stand in for values: every value but the first of an object or array
// follows a comma, and every member value follows a colon. jsonCost assumes b
// is valid JSON. json.Unmarshal checks its whole input before it decodes any of
// it, so for invalid input it allocates nothing and the bound is moot.
func jsonCost(b []byte) uint64 {
	var objects, arrays, seps, strs, strBytes uint64
	inString, escaped := false, false
	for _, c := range b {
		if inString {
			switch {
			case escaped:
				escaped = false
				strBytes++
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			default:
				strBytes++
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			strs++
		case '{':
			objects++
		case '[':
			arrays++
		case ',', ':':
			seps++
		}
	}
	return jsonBaseCost + objects*jsonObjectCost + arrays*jsonArrayCost + seps*jsonSepCost +
		strs*jsonStringCost + strBytes + strBytes/8
}
