package v3engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

const poisonContentHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// proofMismatchAds builds three UHRP advertisements for poisonContentHash.
// Two spend A:0 and A:1 of a parent A
// mined in block 2, a block of four transactions; the one spending A:shortVout
// proves A with a one-level path listing all four leaves, the other with the
// block's normal two-level path. Each of their BEEFs is valid on its own, but
// go-sdk v1.7.7 panics merging the two-level proof into a BEEF that already
// holds the one-level one (merklepath.go:480). The third, honest, spends
// overlaytest's funding output, mined in block 1.
func proofMismatchAds(t *testing.T, shortVout uint32) (short, tall, honest *transaction.Transaction) {
	t.Helper()
	empty, opTrue := script.Script{}, script.Script{script.OpTRUE}
	a := transaction.NewTransaction()
	a.AddInputFromTx(overlaytest.FundingTx(), 0, nil)
	a.Inputs[0].UnlockingScript = &empty
	a.AddOutput(&transaction.TransactionOutput{LockingScript: &opTrue, Satoshis: 40_000})
	a.AddOutput(&transaction.TransactionOutput{LockingScript: &opTrue, Satoshis: 40_000})
	leaves := []*chainhash.Hash{a.TxID()}
	for i := byte(1); i < 4; i++ {
		h := chainhash.DoubleHashH([]byte{i, 0xcc})
		leaves = append(leaves, &h)
	}
	isTxid := true
	shortPath := transaction.NewMerklePath(2, [][]*transaction.PathElement{{
		{Offset: 0, Hash: leaves[0], Txid: &isTxid}, {Offset: 1, Hash: leaves[1]},
		{Offset: 2, Hash: leaves[2]}, {Offset: 3, Hash: leaves[3]},
	}})
	tallPath := transaction.NewMerklePath(2, [][]*transaction.PathElement{
		{{Offset: 0, Hash: leaves[0], Txid: &isTxid}, {Offset: 1, Hash: leaves[1]}},
		{{Offset: 1, Hash: transaction.MerkleTreeParent(leaves[2], leaves[3])}},
	})
	spend := func(vout uint32, mp *transaction.MerklePath) *transaction.Transaction {
		proven := transaction.NewTransaction()
		proven.Version, proven.Inputs, proven.Outputs, proven.LockTime = a.Version, a.Inputs, a.Outputs, a.LockTime
		proven.MerklePath = mp
		x := transaction.NewTransaction()
		x.AddInputFromTx(proven, vout, nil)
		x.Inputs[0].UnlockingScript = &empty
		x.AddOutput(&transaction.TransactionOutput{LockingScript: uhrpAd(t, fmt.Sprintf("https://a.test/%d", vout)), Satoshis: 0})
		return x
	}
	short, tall = spend(shortVout, shortPath), spend(1-shortVout, tallPath)
	honest = overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: uhrpAd(t, "https://a.test/honest"), Satoshis: 0})
	return short, tall, honest
}

// uhrpAd returns a BRC-26 UHRP advertisement for poisonContentHash at url.
func uhrpAd(t *testing.T, url string) *script.Script {
	t.Helper()
	hash, err := hex.DecodeString(poisonContentHash)
	if err != nil {
		t.Fatal(err)
	}
	b := append([]byte{0x00, 0x6a, byte(len(topics.UHRPProtocolID))}, topics.UHRPProtocolID...)
	b = append(append(b, byte(len(hash))), hash...)
	b = append(append(b, byte(len(url))), url...)
	b = append(append(b, byte(len("image/png"))), "image/png"...)
	s := script.Script(b)
	return &s
}

// atomicBEEF returns tx's Atomic BEEF, as engine.Lookup answers it.
func atomicBEEF(t *testing.T, tx *transaction.Transaction) []byte {
	t.Helper()
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixedAnswerLookup is a lookup-service seam that hands raw answer BEEFs to
// the aggregate writer without putting them through local storage.
type fixedAnswerLookup struct {
	engine.LookupService
	answer *lookup.LookupAnswer
}

func (l fixedAnswerLookup) Lookup(context.Context, *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return l.answer, nil
}

// TestAggregatedLookup_StoredProofMismatchKeepsEveryOutput sends conflicting
// raw BEEFs through a registered lookup service. One merge fails, and the
// aggregate guard must answer with every original output as JSON.
func TestAggregatedLookup_StoredProofMismatchKeepsEveryOutput(t *testing.T) {
	short, tall, honest := proofMismatchAds(t, 0)
	answer := &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: []*lookup.OutputListItem{
		{Beef: atomicBEEF(t, short)}, {Beef: atomicBEEF(t, tall)}, {Beef: atomicBEEF(t, honest)},
	}}
	if _, err := aggregateOutputs(usableOutputs(answer.Outputs)); err == nil {
		t.Fatal("fixture must make the raw BEEF merge fail")
	}

	eng, _ := newTestEngine(t)
	eng.RegisterLookupService("ls_raw_proofs", fixedAnswerLookup{answer: answer})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/lookup", strings.NewReader(`{"service":"ls_raw_proofs","query":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-aggregation", "yes")
	NewHandlers(eng).Lookup(rec, req)

	var got lookup.LookupAnswer
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("want the per-output JSON fallback, got %d %q", rec.Code, ct)
	}
	if rec.Code != http.StatusOK || len(got.Outputs) != len(answer.Outputs) {
		t.Fatalf("want all %d outputs, got %d (status %d)", len(answer.Outputs), len(got.Outputs), rec.Code)
	}
	for i := range answer.Outputs {
		if !bytes.Equal(got.Outputs[i].Beef, answer.Outputs[i].Beef) || got.Outputs[i].OutputIndex != answer.Outputs[i].OutputIndex {
			t.Fatalf("output %d differs from the lookup answer", i)
		}
	}
}

// TestStoredProofMismatchNormalizesForAggregation confirms that the same
// conflicting proofs hydrate from storage in canonical form and merge in
// either order.
func TestStoredProofMismatchNormalizesForAggregation(t *testing.T) {
	db, err := leveldb.OpenFile(filepath.Join(t.TempDir(), "storage"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := anvilstorage.New(db)
	short, tall, _ := proofMismatchAds(t, 0)

	load := func(tx *transaction.Transaction) *lookup.OutputListItem {
		t.Helper()
		beef, err := transaction.NewBeefFromTransaction(tx)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.InsertOutputs(context.Background(), topics.UHRPTopicName, tx.TxID(), []uint32{0}, nil, beef, nil); err != nil {
			t.Fatal(err)
		}
		out, err := st.FindOutput(context.Background(), &transaction.Outpoint{Txid: *tx.TxID()}, nil, nil, true)
		if err != nil || out.Beef == nil {
			t.Fatalf("hydrate stored BEEF: %v", err)
		}
		atomic, err := out.Beef.AtomicBytes(tx.TxID())
		if err != nil {
			t.Fatal(err)
		}
		return &lookup.OutputListItem{Beef: atomic}
	}
	storedShort, storedTall := load(short), load(tall)
	for _, outputs := range [][]*lookup.OutputListItem{{storedShort, storedTall}, {storedTall, storedShort}} {
		rec := httptest.NewRecorder()
		if err := writeAggregatedAnswer(rec, &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: outputs}); err != nil {
			t.Fatal(err)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Fatalf("stored proofs must aggregate in either order, got %q", ct)
		}
	}
}

// TestWriteAggregatedAnswer_SkipsUnusableOutputs: an output with no BEEF, or
// one that does not parse, is skipped; an answer whose merge fails falls back
// to per-output BEEFs with every usable output, in order; an answer that
// merges stays binary.
func TestWriteAggregatedAnswer_SkipsUnusableOutputs(t *testing.T) {
	short, tall, honest := proofMismatchAds(t, 0)
	item := func(tx *transaction.Transaction) *lookup.OutputListItem {
		return &lookup.OutputListItem{Beef: atomicBEEF(t, tx)}
	}
	unusable := func() []*lookup.OutputListItem {
		return []*lookup.OutputListItem{nil, {}, {Beef: []byte{0x01, 0x00, 0xbe, 0xef, 0xff}}}
	}

	rec := httptest.NewRecorder()
	poisoned := append(append([]*lookup.OutputListItem{item(short)}, unusable()...), item(tall), item(honest))
	if err := writeAggregatedAnswer(rec, &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: poisoned}); err != nil {
		t.Fatal(err)
	}
	var got lookup.LookupAnswer
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("want the per-output JSON fallback, got %d %q", rec.Code, ct)
	}
	want := []*lookup.OutputListItem{poisoned[0], poisoned[4], poisoned[5]}
	if rec.Code != http.StatusOK || got.Type != lookup.AnswerTypeOutputList || len(got.Outputs) != len(want) {
		t.Fatalf("want %d outputs, got %d (status %d, type %q)", len(want), len(got.Outputs), rec.Code, got.Type)
	}
	for i := range want {
		if !bytes.Equal(got.Outputs[i].Beef, want[i].Beef) || got.Outputs[i].OutputIndex != want[i].OutputIndex {
			t.Fatalf("output %d differs from the answer's own", i)
		}
	}

	for _, tc := range []struct {
		outputs []*lookup.OutputListItem
		count   byte
	}{
		{[]*lookup.OutputListItem{item(tall), item(short), item(honest)}, 3},
		{unusable(), 0},
	} {
		rec := httptest.NewRecorder()
		if err := writeAggregatedAnswer(rec, &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: tc.outputs}); err != nil {
			t.Fatal(err)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
			t.Fatalf("an answer that merges must stay binary, got %q", ct)
		}
		if body := rec.Body.Bytes(); len(body) == 0 || body[0] != tc.count {
			t.Fatalf("want %d outpoints in the binary answer, got %x", tc.count, body)
		}
	}
}

// TestWriteAggregatedAnswer_ContainsGoSDKPanics: a panic in go-sdk's parser
// skips that output, and a panic in its serialiser falls back to per-output
// BEEFs. Neither escapes writeAggregatedAnswer.
func TestWriteAggregatedAnswer_ContainsGoSDKPanics(t *testing.T) {
	_, tall, honest := proofMismatchAds(t, 0)
	answer := &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: []*lookup.OutputListItem{
		{Beef: atomicBEEF(t, tall)}, {Beef: atomicBEEF(t, honest)},
	}}
	parse, serialise := parseAnswerBEEF, serialiseAggregate
	t.Cleanup(func() { parseAnswerBEEF, serialiseAggregate = parse, serialise })

	parseAnswerBEEF = func(b []byte) (*transaction.Transaction, error) {
		if bytes.Equal(b, answer.Outputs[1].Beef) {
			panic("parser bug")
		}
		return parse(b)
	}
	rec := httptest.NewRecorder()
	if err := writeAggregatedAnswer(rec, answer); err != nil {
		t.Fatal(err)
	}
	if body := rec.Body.Bytes(); rec.Header().Get("Content-Type") != "application/octet-stream" || len(body) == 0 || body[0] != 1 {
		t.Fatalf("a parser panic must skip only that output, got %q %x", rec.Header().Get("Content-Type"), rec.Body.Bytes())
	}

	parseAnswerBEEF = parse
	serialiseAggregate = func(*transaction.Beef) ([]byte, error) { panic("serialiser bug") }
	rec = httptest.NewRecorder()
	if err := writeAggregatedAnswer(rec, answer); err != nil {
		t.Fatal(err)
	}
	var got lookup.LookupAnswer
	if rec.Header().Get("Content-Type") != "application/json" || json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got.Outputs) != 2 {
		t.Fatalf("a serialiser panic must fall back to both outputs' own BEEFs, got %q %s", rec.Header().Get("Content-Type"), rec.Body.Bytes())
	}
}
