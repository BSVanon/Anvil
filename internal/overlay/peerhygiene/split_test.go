package peerhygiene

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// minedTxs returns n transactions mined at distinct random positions of one
// block of 2^levels transactions, each with the merkle path its submitter
// would send: its own leaf and sibling, then one sibling per level. Each has
// one input and a locking script of lockLen bytes. The tree is sparse: every
// node off the transactions' paths is a random hash, and the nodes on them are
// hashed up from those, so all n paths prove the same root.
func minedTxs(t testing.TB, n, levels, lockLen int, seed int64) []*transaction.Transaction {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	txs := make([]*transaction.Transaction, n)
	offsets := make([]uint64, n)
	nodes := make([]map[uint64]chainhash.Hash, levels+1)
	for h := range nodes {
		nodes[h] = make(map[uint64]chainhash.Hash)
	}
	for i := range txs {
		tx := transaction.NewTransaction()
		var prev chainhash.Hash
		rng.Read(prev[:])
		unlock := script.Script(bytes.Repeat([]byte{0x51}, 107))
		tx.AddInput(&transaction.TransactionInput{SourceTXID: &prev, UnlockingScript: &unlock, SequenceNumber: 0xffffffff})
		lock := make(script.Script, lockLen)
		binary.LittleEndian.PutUint64(lock, uint64(seed)<<32|uint64(i))
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
		for {
			offsets[i] = uint64(rng.Int63n(1 << levels))
			if _, taken := nodes[0][offsets[i]]; !taken {
				break
			}
		}
		nodes[0][offsets[i]] = *tx.TxID()
		txs[i] = tx
	}
	random := func() chainhash.Hash {
		var h chainhash.Hash
		rng.Read(h[:])
		return h
	}
	for h := 0; h < levels; h++ {
		for off := range nodes[h] {
			if _, ok := nodes[h][off^1]; !ok {
				nodes[h][off^1] = random()
			}
		}
		for off, hash := range nodes[h] {
			if off&1 == 0 {
				right := nodes[h][off+1]
				nodes[h+1][off>>1] = *transaction.MerkleTreeParent(&hash, &right)
			}
		}
	}
	for i, tx := range txs {
		isTxid := true
		path := make([][]*transaction.PathElement, levels)
		for h := 0; h < levels; h++ {
			sib := (offsets[i] >> h) ^ 1
			hash := nodes[h][sib]
			path[h] = []*transaction.PathElement{{Offset: sib, Hash: &hash}}
		}
		own := &transaction.PathElement{Offset: offsets[i], Hash: tx.TxID(), Txid: &isTxid}
		if offsets[i]&1 == 0 {
			path[0] = []*transaction.PathElement{own, path[0][0]}
		} else {
			path[0] = append(path[0], own)
		}
		tx.MerklePath = transaction.NewMerklePath(900_000, path)
	}
	return txs
}

// aggregate writes the aggregated binary answer the way overlay nodes do
// (ts-stack, and v3engine's writeAggregatedAnswer): one outpoint per output,
// then every output's BEEF merged into one, which folds same-block proofs
// into one compound BUMP. outputs[i] names output index[i] of txs[i].
func aggregate(t testing.TB, txs []*transaction.Transaction, index []uint32) []byte {
	t.Helper()
	var head bytes.Buffer
	head.Write(util.VarInt(len(txs)).Bytes())
	merged := transaction.NewBeef()
	for i, tx := range txs {
		txid := tx.TxID()
		for j := len(txid) - 1; j >= 0; j-- {
			head.WriteByte(txid[j])
		}
		head.Write(util.VarInt(index[i]).Bytes())
		head.WriteByte(0)
		beef, err := tx.BEEF()
		if err != nil {
			t.Fatalf("BEEF: %v", err)
		}
		if err := merged.MergeBeefBytes(beef); err != nil {
			t.Fatalf("MergeBeefBytes: %v", err)
		}
	}
	shared, err := merged.Bytes()
	if err != nil {
		t.Fatalf("Beef.Bytes: %v", err)
	}
	return append(head.Bytes(), shared...)
}

// upstreamExpansion is what go-sdk v1.7.7's facilitator would allocate for
// the outputs of a binary answer: every outpoint's tx.BEEF() from the shared
// BEEF, unsplit.
func upstreamExpansion(t testing.TB, body []byte, n int) int {
	t.Helper()
	r := util.NewReader(body)
	if _, err := r.ReadVarInt(); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, n)
	for i := range ids {
		b, _ := r.ReadBytes(32)
		_, _ = r.ReadVarInt()
		_, _ = r.ReadVarInt()
		ids[i] = chainhash.Hash(reverse(b)).String()
	}
	beef, err := transaction.NewBeefFromBytes(r.Data[r.Pos:])
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, id := range ids {
		b, err := beef.FindTransaction(id).BEEF()
		if err != nil {
			t.Fatal(err)
		}
		total += len(b)
	}
	return total
}

func reverse(b []byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b[31-i]
	}
	return out
}

func zeros(n int) []uint32 { return make([]uint32, n) }

// TestSplitProofs_HonestSameBlockAnswerPasses: 256 advertisements of about
// 1.9 KB, the average size of the SHIP and SLAP advertisements on anvil-a,
// mined in one block of 2^20 transactions. Merged into one compound BUMP by
// aggregation, go-sdk would rebuild them into an answer that grows as n
// squared; split, every output's BEEF is again byte for byte the one its
// submitter built, the answer passes, and go-sdk decodes the JSON handed on
// in its place to the same outputs.
func TestSplitProofs_HonestSameBlockAnswerPasses(t *testing.T) {
	const n = 256
	txs := minedTxs(t, n, 20, 1_800, 1)
	body := aggregate(t, txs, zeros(n))
	answer, err := decodeLookupAnswer(binaryContentType, body)
	if err != nil {
		t.Fatalf("an honest same-block answer must pass: %v", err)
	}
	total := 0
	for i, out := range answer.Outputs {
		if want := txBEEF(t, txs[i]); !bytes.Equal(out.Beef, want) {
			t.Fatalf("output %d: rebuilt BEEF is %d bytes, its submitter's %d", i, len(out.Beef), len(want))
		}
		total += len(out.Beef)
	}
	upstream := upstreamExpansion(t, body, n)
	t.Logf("%d same-block outputs: body %d bytes, split outputs %d bytes (cap %d), unsplit %d bytes",
		n, len(body), total, MaxAnswerBEEFBytes, upstream)
	if int64(upstream) <= MaxAnswerBEEFBytes {
		t.Fatalf("unsplit, the answer should come to more than the cap; it came to %d bytes", upstream)
	}

	outType, handed, err := PrepareLookupAnswer(binaryContentType, body)
	if err != nil || outType != "application/json" {
		t.Fatalf("PrepareLookupAnswer: %q, %v", outType, err)
	}
	var decoded lookup.LookupAnswer
	if err := json.Unmarshal(handed, &decoded); err != nil {
		t.Fatalf("the answer handed on must decode as JSON: %v", err)
	}
	if !reflect.DeepEqual(&decoded, answer) {
		t.Fatal("the answer handed on decodes to other outputs than the ones checked")
	}
}

// TestSplitProofs_HostileSameBlockAnswerRefused: the same answer with one
// level of its compound BUMP removed. No transaction's own path can be
// rebuilt, so each keeps the compound BUMP, and the outputs come to more than
// MaxAnswerBEEFBytes, as go-sdk would build them.
func TestSplitProofs_HostileSameBlockAnswerRefused(t *testing.T) {
	const n = 256
	txs := minedTxs(t, n, 20, 1_800, 1)
	body := aggregate(t, txs, zeros(n))
	head := len(body) - len(sharedOf(t, body, n))
	beef, err := transaction.NewBeefFromBytes(body[head:])
	if err != nil || len(beef.BUMPs) != 1 {
		t.Fatalf("want one compound BUMP: %d, %v", len(beef.BUMPs), err)
	}
	beef.BUMPs[0].Path[10] = nil
	shared, err := beef.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	hostile := append(append([]byte{}, body[:head]...), shared...)
	_, err = decodeLookupAnswer(binaryContentType, hostile)
	if err == nil || !strings.Contains(err.Error(), "re-serialized BEEF exceeds capacity") {
		t.Fatalf("want the answer refused by MaxAnswerBEEFBytes, got: %v", err)
	}
}

// sharedOf returns the shared BEEF of a binary answer of n outpoints without
// contexts.
func sharedOf(t testing.TB, body []byte, n int) []byte {
	t.Helper()
	r := util.NewReader(body)
	if _, err := r.ReadVarInt(); err != nil {
		t.Fatal(err)
	}
	r.Pos += n * (32 + 1 + 1)
	return r.Data[r.Pos:]
}

// spender returns a transaction spending output 0 of each parent, in order.
func spender(parents ...*transaction.Transaction) *transaction.Transaction {
	tx := transaction.NewTransaction()
	for _, p := range parents {
		tx.AddInputFromTx(p, 0, nil)
		tx.Inputs[len(tx.Inputs)-1].UnlockingScript = &script.Script{}
	}
	lock := script.Script{script.OpTRUE}
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
	return tx
}

// TestOutputBEEF_DoesNotChangeOtherOutputs: T2 spends P2 and P1, mined in
// one block, and T1 spends P1 alone. go-sdk's Transaction.BEEF would combine
// P2's proof into P1's own MerklePath while writing T2, so T1, written after,
// would carry both proofs. Each output's BEEF must be the one its own
// ancestry gives.
func TestOutputBEEF_DoesNotChangeOtherOutputs(t *testing.T) {
	parents := minedTxs(t, 2, 20, 100, 2)
	t1, t2 := spender(parents[0]), spender(parents[1], parents[0])
	want := txBEEF(t, t1)
	answer, err := decodeLookupAnswer(binaryContentType, aggregate(t, []*transaction.Transaction{t2, t1}, zeros(2)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := answer.Outputs[1].Beef; !bytes.Equal(got, want) {
		t.Fatalf("T1's BEEF is %d bytes, written alone it is %d: writing T2 changed it", len(got), len(want))
	}
}

// combineAnswer is one output spending m parents mined in one block, then
// copies more outpoints naming it again.
func combineAnswer(t testing.TB, m, copies int) []byte {
	t.Helper()
	tip := spender(minedTxs(t, m, 20, 10, 3)...)
	txs := make([]*transaction.Transaction, copies+1)
	for i := range txs {
		txs[i] = tip
	}
	return aggregate(t, txs, zeros(len(txs)))
}

// TestOutputBEEF_CombineWorkIsBudgeted: an output whose ancestry holds 1,000
// proofs from one block is refused while it is being rebuilt, before its
// combined proof is finished, and one with 40 passes.
func TestOutputBEEF_CombineWorkIsBudgeted(t *testing.T) {
	if _, err := decodeLookupAnswer(binaryContentType, combineAnswer(t, 40, 0)); err != nil {
		t.Fatalf("40 same-block parents must pass: %v", err)
	}
	_, err := decodeLookupAnswer(binaryContentType, combineAnswer(t, 1_000, 0))
	if !errors.Is(err, errCombineBudget) || !strings.HasPrefix(err.Error(), "binary lookup: re-serializing BEEF") {
		t.Fatalf("want the output refused while rebuilding it, got: %v", err)
	}
}

// TestParseWork_RepeatsCountAgainstBudget: go-sdk's resolver parses every
// output, so every outpoint naming an output whose parse combines proofs
// counts that work again. One such output passes; enough repeats of it to
// pass MaxAnswerCombineWork are refused, though their bytes are well within
// MaxAnswerBEEFBytes.
func TestParseWork_RepeatsCountAgainstBudget(t *testing.T) {
	const m = 200
	tip := spender(minedTxs(t, m, 20, 10, 3)...)
	_, work, err := outputBEEF(tip, *tip.TxID(), &combineBudget{max: MaxAnswerCombineWork})
	if err != nil || work == 0 {
		t.Fatalf("outputBEEF: work %d, %v", work, err)
	}
	if _, err := decodeLookupAnswer(binaryContentType, combineAnswer(t, m, 0)); err != nil {
		t.Fatalf("one output must pass: %v", err)
	}
	copies := int(MaxAnswerCombineWork/work) + 1
	_, err = decodeLookupAnswer(binaryContentType, combineAnswer(t, m, copies))
	if !errors.Is(err, errCombineBudget) {
		t.Fatalf("%d outpoints of %d parse work each: want them refused, got: %v", copies+1, work, err)
	}
}

// TestCombineWork_CapBoundsParseTime measures go-sdk's ParseBeef on output
// BEEFs whose parse work comes to MaxAnswerCombineWork in all, the most an
// accepted answer can make go-sdk's resolver spend combining.
func TestCombineWork_CapBoundsParseTime(t *testing.T) {
	const m = 120
	tip := spender(minedTxs(t, m, 20, 10, 4)...)
	beef, work, err := outputBEEF(tip, *tip.TxID(), &combineBudget{max: MaxAnswerCombineWork})
	if err != nil {
		t.Fatalf("outputBEEF: %v", err)
	}
	parses := int(MaxAnswerCombineWork / work)
	start := time.Now()
	for i := 0; i < parses; i++ {
		if _, _, _, err := transaction.ParseBeef(beef); err != nil {
			t.Fatalf("ParseBeef: %v", err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("%d parses of %d work each (%d in all): %v, %.1f ns per path element",
		parses, work, uint64(parses)*work, elapsed, float64(elapsed.Nanoseconds())/float64(uint64(parses)*work))
	if elapsed > 2*time.Second {
		t.Fatalf("parsing at the cap took %v, want under 2s", elapsed)
	}
}

// TestEncodeOutputList_MatchesEncodingJSON: the answer handed on in place of
// a binary one is what json.Marshal writes for it, byte for byte, with and
// without outputs, and its buffer is exactly its length.
func TestEncodeOutputList_MatchesEncodingJSON(t *testing.T) {
	txs := minedTxs(t, 3, 20, 50, 5)
	for _, outs := range [][]*lookup.OutputListItem{
		nil,
		{{Beef: txBEEF(t, txs[0]), OutputIndex: 0}},
		{{Beef: txBEEF(t, txs[0]), OutputIndex: 7}, {Beef: txBEEF(t, txs[1]), OutputIndex: 4294967295}, {Beef: []byte{0xff, 0xfe}, OutputIndex: 12}},
	} {
		want, err := json.Marshal(&lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: outs})
		if err != nil {
			t.Fatal(err)
		}
		got := encodeOutputList(outs)
		if !bytes.Equal(got, want) || cap(got) != len(got) {
			t.Fatalf("encodeOutputList (cap %d):\n got  %s\n want %s", cap(got), got, want)
		}
	}
}
