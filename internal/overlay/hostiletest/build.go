package hostiletest

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// Costliest returns n replies, alternating binary and JSON, each as costly to
// decode as peerhygiene's caps let through. Reply i is named good-<i>, two
// digits, and advertises c.Host of its name.
//
// A binary reply lists MaxLookupOutputs outpoints: the marker, then one small
// transaction named over and over, sized so the outputs' re-serialized BEEF
// just fits MaxAnswerBEEFBytes. Its shared BEEF is padded with empty
// transactions, the shape peerhygiene prices highest per byte, until it just
// fits MaxBEEFParseCost, and the first outpoint's context pads the body to
// MaxLookupResponseBytes. A JSON reply lists the marker and carries a result
// string as long as MaxJSONDecodeCost allows: of everything a JSON answer can
// hold, a string keeps the most memory per byte of cost.
func Costliest(t testing.TB, c *Canary, n int) []*Reply {
	t.Helper()
	name := func(i int) string { return fmt.Sprintf("good-%02d", i) }
	first := slapAd(c.Host(name(0)))
	k := newKit(t, first)
	// The names are all as long, so the result length found for the first
	// marker fits every marker.
	resultLen := largest(t, peerhygiene.MaxLookupResponseBytes, 256, func(n int64) *Reply {
		return jsonReply("probe", first, nil, longString(n))
	})
	replies := make([]*Reply, n)
	for i := range replies {
		ad := slapAd(c.Host(name(i)))
		if i%2 == 0 {
			replies[i] = k.binary(name(i), ad, peerhygiene.MaxLookupResponseBytes)
		} else {
			replies[i] = jsonReply(name(i), ad, nil, longString(resultLen))
		}
		if i < 2 {
			if err := peerhygiene.ValidateLookupAnswer(replies[i].ContentType, replies[i].Bytes()); err != nil {
				t.Fatalf("hostiletest: the guard must accept %s: %v", name(i), err)
			}
		}
	}
	return replies
}

// PastTheCaps returns one reply past each per-answer cap, named for that cap
// and advertising c.Host of its name. Each passes every cap but its own, so
// the guard refuses it only for as long as that cap is in place, and each is
// sized so that letting it through costs far more than the caps allow. No
// reply is past MaxLookupOutputs in JSON: MaxJSONDecodeCost prices an output
// at no less than 592 bytes, so it admits no more than about 3,500.
func PastTheCaps(t testing.TB, c *Canary) []*Reply {
	t.Helper()
	ad := func(name string) *transaction.Transaction { return slapAd(c.Host(name)) }
	var out []*Reply

	// Four times MaxLookupOutputs, each output's BEEF the smallest there is.
	a, tiny := ad("past-outputs"), pushTx(2, 0)
	out = append(out, binaryReply("past-outputs", a, tiny, 4*peerhygiene.MaxLookupOutputs, 0, fillerBEEF(0, a, tiny)))

	// A shared BEEF of nearly 2 MiB of empty transactions.
	a = ad("past-parse-cost")
	out = append(out, binaryReply("past-parse-cost", a, nil, 1, 0,
		fillerBEEF(int((peerhygiene.MaxLookupResponseBytes-4096)/11), a)))

	// 64 more outpoints naming a transaction with a 1.25 MB output, which
	// go-sdk re-serializes once for each.
	a, big := ad("past-answer-beef"), pushTx(3, 1_250_000)
	out = append(out, binaryReply("past-answer-beef", a, big, 65, 0, fillerBEEF(0, a, big)))

	// The costliest binary reply, padded to 24 MiB.
	a = ad("past-body")
	out = append(out, newKit(t, a).binary("past-body", a, 24<<20))

	// A JSON result of nearly 2 MiB of {"":0}, which decoding amplifies some
	// fiftyfold.
	objects := (peerhygiene.MaxLookupResponseBytes - 4096) / 7
	out = append(out, jsonReply("past-json-cost", ad("past-json-cost"), nil,
		[]piece{{[]byte("["), 1}, {[]byte(`{"":0},`), objects}, {[]byte(`{"":0}]`), 1}}))

	// Two outputs of a transaction with a 600 KB output.
	bigBEEF := beefOf(pushTx(4, 600_000))
	out = append(out, jsonReply("past-json-beef", ad("past-json-beef"), [][]byte{bigBEEF, bigBEEF}, nil))

	// An output whose BEEF is nearly 1 MiB of empty transactions.
	filler := fillerBEEF(int((peerhygiene.MaxAnswerBEEFBytes-4096)/11), pushTx(5, 0))
	out = append(out, jsonReply("past-json-parse-cost", ad("past-json-parse-cost"), [][]byte{filler}, nil))
	return out
}

// kit holds the sizes that make a binary reply just fit the caps.
type kit struct {
	small  *transaction.Transaction // named by every outpoint but the first
	filler int                      // empty transactions in the shared BEEF
}

func newKit(t testing.TB, ad *transaction.Transaction) *kit {
	t.Helper()
	k := &kit{}
	// The largest small transaction whose BEEF, MaxLookupOutputs-1 times
	// over, fits MaxAnswerBEEFBytes beside the marker's.
	room := peerhygiene.MaxAnswerBEEFBytes - int64(len(beefOf(ad)))
	for n := 0; ; n++ {
		if int64(len(beefOf(pushTx(1, n+1))))*(peerhygiene.MaxLookupOutputs-1) > room {
			k.small = pushTx(1, n)
			break
		}
	}
	k.filler = int(largest(t, peerhygiene.MaxBEEFParseCost/64, 1, func(f int64) *Reply {
		return binaryReply("probe", ad, k.small, 2, 0, fillerBEEF(int(f), ad, k.small))
	}))
	return k
}

// largest finds, to within step, the largest n in [0, hi] for which the guard
// accepts build(n). It needs build(0) accepted. If the guard accepts even
// build(hi), as it does once a cap is taken out, it returns hi.
func largest(t testing.TB, hi, step int64, build func(int64) *Reply) int64 {
	t.Helper()
	ok := func(n int64) bool {
		r := build(n)
		return peerhygiene.ValidateLookupAnswer(r.ContentType, r.Bytes()) == nil
	}
	if !ok(0) {
		t.Fatalf("hostiletest: the guard refuses even the smallest reply")
	}
	if ok(hi) {
		t.Logf("hostiletest: the guard accepts a reply sized %d, the most this test builds", hi)
		return hi
	}
	lo := int64(0)
	for hi-lo > step {
		if mid := (lo + hi) / 2; ok(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

// binary is the costliest binary reply for ad, its first context padding the
// body to size bytes.
func (k *kit) binary(name string, ad *transaction.Transaction, size int64) *Reply {
	beef := fillerBEEF(k.filler, ad, k.small)
	unpadded := binaryReply(name, ad, k.small, peerhygiene.MaxLookupOutputs, 0, beef).Len()
	// A context length of 64 KiB or more takes a 5-byte varint, not 1.
	return binaryReply(name, ad, k.small, peerhygiene.MaxLookupOutputs, size-unpadded-4, beef)
}

// binaryReply is the aggregated binary answer format: count outpoints, the
// first naming output 0 of first, with pad bytes of context, and the rest
// output 0 of rest; then beef.
func binaryReply(name string, first, rest *transaction.Transaction, count int, pad int64, beef []byte) *Reply {
	r := &Reply{Name: name, ContentType: octetStream, Marker: marker(first)}
	var head bytes.Buffer
	head.Write(util.VarInt(count).Bytes())
	head.Write(txidBytes(first))
	head.WriteByte(0)
	head.Write(util.VarInt(pad).Bytes())
	r.add(head.Bytes(), 1)
	if pad > 0 {
		r.add([]byte{0}, pad)
	}
	if count > 1 {
		r.add(append(txidBytes(rest), 0, 0), int64(count-1))
	}
	r.add(beef, 1)
	return r
}

// jsonReply is an output-list JSON answer: the marker's output, then one
// output per extra BEEF, then, unless result is nil, a result written as the
// pieces of result.
func jsonReply(name string, ad *transaction.Transaction, extra [][]byte, result []piece) *Reply {
	r := &Reply{Name: name, ContentType: "application/json", Marker: marker(ad)}
	r.add([]byte(`{"type":"output-list","outputs":[`), 1)
	for i, beef := range append([][]byte{beefOf(ad)}, extra...) {
		if i > 0 {
			r.add([]byte(","), 1)
		}
		r.add([]byte(`{"beef":"`+base64.StdEncoding.EncodeToString(beef)+`","outputIndex":0}`), 1)
	}
	r.add([]byte("]"), 1)
	if result != nil {
		r.add([]byte(`,"result":`), 1)
		r.pieces = append(r.pieces, result...)
	}
	r.add([]byte("}"), 1)
	return r
}

// longString is a JSON string of n letters.
func longString(n int64) []piece {
	return []piece{{[]byte(`"`), 1}, {[]byte("a"), n}, {[]byte(`"`), 1}}
}

// fillerBEEF is a V1 BEEF of k empty transactions, then txs.
func fillerBEEF(k int, txs ...*transaction.Transaction) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, transaction.BEEF_V1)
	b.WriteByte(0) // no BUMPs
	b.Write(util.VarInt(k + len(txs)).Bytes())
	empty := make([]byte, 11) // version, no inputs, no outputs, lock time 0, no BUMP
	for i := 0; i < k; i++ {
		binary.LittleEndian.PutUint32(empty, uint32(i)+1) // a distinct txid each
		b.Write(empty)
	}
	for _, tx := range txs {
		b.Write(tx.Bytes())
		b.WriteByte(0)
	}
	return b.Bytes()
}

// txidBytes is tx's txid in display order, as the binary format carries it.
func txidBytes(tx *transaction.Transaction) []byte {
	b, _ := hex.DecodeString(tx.TxID().String())
	return b
}
