package peerhygiene

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// beefOf writes a BEEF header for version, then count as a varint, then
// count copies of entry with i (a little-endian uint32) at offset at, so each
// copy is distinct where that matters.
func beefOf(version uint32, head []byte, count int, entry []byte, at int, tail []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, version)
	b.Write(head)
	b.Write(util.VarInt(count).Bytes())
	e := bytes.Clone(entry)
	for i := 0; i < count; i++ {
		if at >= 0 {
			binary.LittleEndian.PutUint32(e[at:], uint32(i))
		}
		b.Write(e)
	}
	b.Write(tail)
	return b.Bytes()
}

// costlyBEEFs are BEEFs of about size bytes in each shape that makes go-sdk's
// parse allocate the most per byte, each built when called.
func costlyBEEFs(size int) map[string]func() []byte {
	v1, v2 := transaction.BEEF_V1, transaction.BEEF_V2
	return map[string]func() []byte{
		// Empty transactions: version, no inputs, no outputs, lock time, no BUMP.
		"empty transactions": func() []byte { return beefOf(v1, []byte{0}, (size-16)/11, make([]byte, 11), 0, nil) },
		"empty V2 transactions": func() []byte {
			return beefOf(v2, []byte{0}, (size-16)/11, append([]byte{0}, make([]byte, 10)...), 1, nil)
		},
		// One transaction of empty outputs.
		"empty outputs": func() []byte {
			return beefOf(v1, []byte{0, 1, 1, 0, 0, 0, 0}, (size-30)/9, make([]byte, 9), -1, make([]byte, 5))
		},
		// One transaction of inputs with empty unlocking scripts.
		"bare inputs": func() []byte {
			return beefOf(v1, []byte{0, 1, 1, 0, 0, 0}, (size-30)/41, make([]byte, 41), 0, make([]byte, 6))
		},
		// One BUMP with one level of duplicate leaves.
		"duplicate leaves": func() []byte { return beefOf(v1, []byte{1, 1, 1}, (size-20)/2, []byte{0, 1}, -1, []byte{0}) },
		// V2 transactions given by txid alone.
		"txid-only transactions": func() []byte {
			return beefOf(v2, []byte{0}, (size-16)/33, append([]byte{2}, make([]byte, 32)...), 1, nil)
		},
		// BUMPs of one empty level.
		"empty BUMPs": func() []byte { return beefOf(v1, nil, (size-16)/3, []byte{1, 1, 0}, -1, []byte{0}) },
	}
}

// adTx is a realistic SHIP or SLAP advertisement as an honest tracker
// returns it: a 107-byte unlock, a 190-byte PushDrop lock, a 25-byte change
// output and a 20-level merkle proof of its own block.
func adTx(i int) *transaction.Transaction {
	tx := transaction.NewTransaction()
	var prev chainhash.Hash
	binary.LittleEndian.PutUint64(prev[:], uint64(i)+1)
	unlock := script.Script(bytes.Repeat([]byte{0x51}, 107))
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &prev, UnlockingScript: &unlock, SequenceNumber: 0xffffffff})
	lock, change := script.Script(bytes.Repeat([]byte{0x52}, 190)), script.Script(bytes.Repeat([]byte{0x53}, 25))
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &change, Satoshis: 1000})
	isTxid := true
	path := make([][]*transaction.PathElement, 20)
	sibling := chainhash.DoubleHashH([]byte{byte(i), byte(i >> 8), 1})
	path[0] = []*transaction.PathElement{{Offset: 4000, Hash: tx.TxID(), Txid: &isTxid}, {Offset: 4001, Hash: &sibling}}
	for level := 1; level < 20; level++ {
		h := chainhash.DoubleHashH([]byte{byte(i), byte(i >> 8), byte(level), 2})
		path[level] = []*transaction.PathElement{{Offset: uint64(4000>>level) ^ 1, Hash: &h}}
	}
	tx.MerklePath = transaction.NewMerklePath(uint32(900000+i), path)
	return tx
}

// floatingGarbage allows for what liveHeap's peak counts beyond the live
// heap: garbage the collector has not reclaimed yet, which at 2% stays well
// under 512 KiB for these parses however large the input. Fitting the slope
// of peak over input size instead (1,600 advertisements against 400) puts
// honest advertisements at about 3,220 heap bytes each against beefCost's
// 4,000.
const floatingGarbage = 512 << 10

// liveHeap runs f with garbage collection at 2% and returns the most heap
// allocated while it ran, sampled from exact snapshots, and what its result
// keeps after a collection, each above the heap before it ran. Garbage not
// yet collected counts towards the peak, so it can only read high, by up to
// floatingGarbage.
func liveHeap(f func() any) (peak, kept uint64) {
	defer debug.SetGCPercent(debug.SetGCPercent(2))
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	base := m.HeapAlloc
	var top atomic.Uint64
	note := func(v uint64) {
		for old := top.Load(); v > old && !top.CompareAndSwap(old, v); old = top.Load() {
		}
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&m)
			note(m.HeapAlloc)
			time.Sleep(50 * time.Microsecond)
		}
	}()
	result := f()
	close(stop)
	<-done
	runtime.ReadMemStats(&m)
	note(m.HeapAlloc)
	runtime.GC()
	runtime.ReadMemStats(&m)
	if m.HeapAlloc > base {
		kept = m.HeapAlloc - base
	}
	runtime.KeepAlive(result)
	if t := top.Load(); t > base {
		peak = t - base
	}
	return peak, kept
}

// TestBeefCost_BoundsWhatGoSDKParsingHolds: for every costly shape, and for an
// answer of 400 honest advertisements, each go-sdk entry point that parses
// lookup BEEFs holds no more heap at its peak, nor keeps more after, than
// beefCost prices.
func TestBeefCost_BoundsWhatGoSDKParsingHolds(t *testing.T) {
	shapes := costlyBEEFs(512 << 10)
	shapes["400 advertisements"] = func() []byte { return adsBEEF(t, 400) }
	parsers := map[string]func([]byte) any{
		"NewBeefFromBytes":       func(b []byte) any { x, _ := transaction.NewBeefFromBytes(b); return x },
		"ParseBeef":              func(b []byte) any { x, y, _, _ := transaction.ParseBeef(b); return []any{x, y} },
		"NewTransactionFromBEEF": func(b []byte) any { x, _ := transaction.NewTransactionFromBEEF(b); return x },
	}
	for name, build := range shapes {
		raw := build()
		cost := beefCost(raw)
		for parser, parse := range parsers {
			peak, kept := liveHeap(func() any { return parse(raw) })
			t.Logf("%-24s %-22s %7d bytes, cost %9d, peak %9d, kept %9d", name, parser, len(raw), cost, peak, kept)
			if peak > cost+floatingGarbage || kept > cost {
				t.Errorf("%s through %s: peak %d or kept %d is over beefCost %d", name, parser, peak, kept, cost)
			}
		}
	}
}

// adsBEEF is a V1 BEEF of n advertisements, each with its own proof.
func adsBEEF(t *testing.T, n int) []byte {
	t.Helper()
	beef := transaction.NewBeefV1()
	for i := 0; i < n; i++ {
		if _, err := beef.MergeTransaction(adTx(i)); err != nil {
			t.Fatalf("MergeTransaction: %v", err)
		}
	}
	raw, err := beef.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return raw
}

// TestJSONCost_BoundsWhatDecodingHolds: for every costly JSON shape, and an
// answer of 300 honest outputs, decoding into a LookupAnswer holds no more
// heap at its peak, nor keeps more after, than jsonCost prices.
func TestJSONCost_BoundsWhatDecodingHolds(t *testing.T) {
	const size = 512 << 10
	result := func(elem string, n int) []byte {
		return []byte(`{"type":"freeform","result":[` + strings.TrimSuffix(strings.Repeat(elem+",", n), ",") + `]}`)
	}
	var keys strings.Builder
	for i := 0; i < size/9; i++ {
		fmt.Fprintf(&keys, `"%x":0,`, i)
	}
	beef, err := adTx(1).BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}
	item, _ := json.Marshal(&lookup.OutputListItem{Beef: beef})
	shapes := map[string][]byte{
		"tiny objects":  result(`{"":0}`, size/7),
		"empty arrays":  result(`[]`, size/3),
		"empty objects": result(`{}`, size/3),
		"zeros":         result(`0`, size/2),
		"empty strings": result(`""`, size/3),
		"nulls":         result(`null`, size/5),
		"nesting":       result(`[[[[0]]]]`, size/10),
		"one long map":  []byte(`{"type":"freeform","result":{` + strings.TrimSuffix(keys.String(), ",") + `}}`),
		"long string":   []byte(`{"type":"freeform","result":"` + strings.Repeat("a", size) + `"}`),
		"empty outputs": []byte(`{"type":"output-list","outputs":[` + strings.Repeat(`{},`, size/3) + `{}]}`),
		"300 outputs":   []byte(`{"type":"output-list","outputs":[` + strings.TrimSuffix(strings.Repeat(string(item)+",", 300), ",") + `]}`),
	}
	for name, raw := range shapes {
		cost := jsonCost(raw)
		peak, kept := liveHeap(func() any {
			answer := &lookup.LookupAnswer{}
			if err := json.Unmarshal(raw, answer); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			return answer
		})
		t.Logf("%-14s %7d bytes, cost %10d, peak %9d, kept %9d", name, len(raw), cost, peak, kept)
		if peak > cost+floatingGarbage || kept > cost {
			t.Errorf("%s: peak %d or kept %d is over jsonCost %d", name, peak, kept, cost)
		}
	}
}

// TestLookupCaps_AdmitHonestAnswers: honest SHIP and SLAP answers pass the
// caps with room to spare. The largest real answers hold tens of
// advertisements, about 70 during the 2026-06 flood; the caps admit 800 in a
// binary answer and 700 in a JSON one.
func TestLookupCaps_AdmitHonestAnswers(t *testing.T) {
	shared := transaction.NewBeefV1()
	var entries []binaryEntry
	var outputs []*lookup.OutputListItem
	for i := 0; i < 800; i++ {
		tx := adTx(i)
		if _, err := shared.MergeTransaction(tx); err != nil {
			t.Fatalf("MergeTransaction: %v", err)
		}
		entries = append(entries, binaryEntry{tx: tx})
		if i < 700 {
			outputs = append(outputs, &lookup.OutputListItem{Beef: txBEEF(t, tx)})
		}
	}
	sharedBytes, err := shared.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	binaryBody := encodeBinaryAnswer(t, sharedBytes, entries...)
	if err := ValidateLookupAnswer(octetStream, binaryBody); err != nil {
		t.Errorf("800 advertisements, binary (%d bytes): %v", len(binaryBody), err)
	}
	if err := ValidateLookupAnswer("application/json", jsonAnswer(t, outputs...)); err != nil {
		t.Errorf("700 advertisements, JSON: %v", err)
	}
}
