package lookups

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

func newLookupDB(t *testing.T) *leveldb.DB {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// buildDEXSwapAdmitPayload builds a tx with output 0 = a real spendable
// P2PKH-ish script and output 1 = the DEX-swap metadata OP_RETURN pointing
// at OfferVout=0. Wraps in atomic BEEF. The lookup admit path receives
// the offer's outpoint and re-scans the tx for the matching metadata.
func buildDEXSwapAdmitPayload(t *testing.T, maker, offeringTokenTxid, requestingTokenTxid string) *engine.OutputAdmittedByTopic {
	t.Helper()
	// Output 0: a plausible spendable script (we just need anything that
	// is NOT bare OP_RETURN; a single OP_TRUE works).
	offerScript := script.Script([]byte{0x51}) // OP_TRUE
	offerOut := &transaction.TransactionOutput{LockingScript: &offerScript, Satoshis: 1}

	// Build DEX-swap metadata payload (matches topics.DEXSwapEntry shape).
	entry := topics.DEXSwapEntry{
		Maker:        maker,
		Offering:     mustJSON(t, map[string]any{"token": map[string]string{"txid": offeringTokenTxid}}),
		Requesting:   mustJSON(t, map[string]any{"token": map[string]string{"txid": requestingTokenTxid}}),
		RefundHeight: 850000,
		OfferVout:    0,
	}
	entryJSON := mustMarshalJSON(t, entry)

	// OP_FALSE OP_RETURN "dex.swap.offer" <version=1> <json>
	mdScript := []byte{0x00, 0x6a}
	mdScript = append(mdScript, byte(len(topics.DEXSwapProtocol)))
	mdScript = append(mdScript, []byte(topics.DEXSwapProtocol)...)
	mdScript = append(mdScript, 1, byte(topics.DEXSwapVersion))
	if len(entryJSON) <= 75 {
		mdScript = append(mdScript, byte(len(entryJSON)))
	} else {
		mdScript = append(mdScript, 0x4c, byte(len(entryJSON)))
	}
	mdScript = append(mdScript, entryJSON...)
	mdScriptObj := script.Script(mdScript)
	mdOut := &transaction.TransactionOutput{LockingScript: &mdScriptObj, Satoshis: 0}

	tx := transaction.NewTransaction()
	tx.AddOutput(offerOut)
	tx.AddOutput(mdOut)

	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	atomic, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return &engine.OutputAdmittedByTopic{
		Topic:       topics.DEXSwapTopicName,
		OutputIndex: 0,
		AtomicBEEF:  atomic,
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func outpointFromAdmitPayload(t *testing.T, p *engine.OutputAdmittedByTopic) *transaction.Outpoint {
	t.Helper()
	_, txid, err := transaction.NewBeefFromAtomicBytes(p.AtomicBEEF)
	if err != nil {
		t.Fatalf("decode atomic beef: %v", err)
	}
	return &transaction.Outpoint{Txid: *txid, Index: p.OutputIndex}
}

// --- DEX-swap tests --------------------------------------------------------

func TestDEXSwap_AdmitAndFilterByMaker(t *testing.T) {
	s := NewDEXSwapLookupService(newLookupDB(t))
	pA := buildDEXSwapAdmitPayload(t, "makerA", "tokA", "tokX")
	pB := buildDEXSwapAdmitPayload(t, "makerB", "tokA", "tokY")
	for _, p := range []*engine.OutputAdmittedByTopic{pA, pB} {
		if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
			t.Fatalf("admit: %v", err)
		}
	}
	q, _ := json.Marshal(topics.DEXSwapLookupQuery{Maker: "makerA"})
	answer, err := s.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.DEXSwapLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 match for makerA, got %d", len(answer.Formulas))
	}
	wantOp := outpointFromAdmitPayload(t, pA)
	if !answer.Formulas[0].Outpoint.Equal(wantOp) {
		t.Fatalf("formula outpoint mismatch")
	}
}

func TestDEXSwap_FilterByOfferingAndRequesting(t *testing.T) {
	s := NewDEXSwapLookupService(newLookupDB(t))
	pA := buildDEXSwapAdmitPayload(t, "x", "BSV21_A", "BSV21_X")
	pB := buildDEXSwapAdmitPayload(t, "y", "BSV21_B", "BSV21_X")
	for _, p := range []*engine.OutputAdmittedByTopic{pA, pB} {
		if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
			t.Fatalf("admit: %v", err)
		}
	}
	q1, _ := json.Marshal(topics.DEXSwapLookupQuery{OfferingTokenTxid: "BSV21_A"})
	a1, _ := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.DEXSwapLookupServiceName, Query: q1})
	if len(a1.Formulas) != 1 {
		t.Fatalf("OfferingTokenTxid filter: expected 1, got %d", len(a1.Formulas))
	}
	q2, _ := json.Marshal(topics.DEXSwapLookupQuery{RequestingTokenTxid: "BSV21_X"})
	a2, _ := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.DEXSwapLookupServiceName, Query: q2})
	if len(a2.Formulas) != 2 {
		t.Fatalf("RequestingTokenTxid filter: expected 2, got %d", len(a2.Formulas))
	}
}

func TestDEXSwap_ListAll(t *testing.T) {
	s := NewDEXSwapLookupService(newLookupDB(t))
	for _, m := range []string{"m1", "m2", "m3"} {
		p := buildDEXSwapAdmitPayload(t, m, "o", "r")
		if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
			t.Fatalf("admit: %v", err)
		}
	}
	q, _ := json.Marshal(topics.DEXSwapLookupQuery{List: "all"})
	answer, err := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.DEXSwapLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(answer.Formulas) != 3 {
		t.Fatalf("list all expected 3, got %d", len(answer.Formulas))
	}
}

func TestDEXSwap_OutputSpentRemovesEntry(t *testing.T) {
	s := NewDEXSwapLookupService(newLookupDB(t))
	p := buildDEXSwapAdmitPayload(t, "m", "o", "r")
	if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := outpointFromAdmitPayload(t, p)
	if err := s.OutputSpent(context.Background(), &engine.OutputSpent{Outpoint: op, Topic: topics.DEXSwapTopicName}); err != nil {
		t.Fatalf("spend: %v", err)
	}
	q, _ := json.Marshal(topics.DEXSwapLookupQuery{List: "all"})
	a, _ := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.DEXSwapLookupServiceName, Query: q})
	if len(a.Formulas) != 0 {
		t.Fatalf("expected 0 after spend, got %d", len(a.Formulas))
	}
}

func TestDEXSwap_WrongTopicIgnored(t *testing.T) {
	s := NewDEXSwapLookupService(newLookupDB(t))
	p := buildDEXSwapAdmitPayload(t, "m", "o", "r")
	p.Topic = topics.UHRPTopicName
	if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
		t.Fatalf("admit: %v", err)
	}
	q, _ := json.Marshal(topics.DEXSwapLookupQuery{List: "all"})
	a, _ := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.DEXSwapLookupServiceName, Query: q})
	if len(a.Formulas) != 0 {
		t.Fatalf("wrong-topic admit should be ignored")
	}
}

func TestDEXSwap_DocsAndMetaCompile(t *testing.T) {
	s := NewDEXSwapLookupService(newLookupDB(t))
	if s.GetDocumentation() == "" {
		t.Fatalf("docs empty")
	}
	if s.GetMetaData() == nil || s.GetMetaData().Name != topics.DEXSwapLookupServiceName {
		t.Fatalf("meta mismatch")
	}
	var _ engine.LookupService = (*DEXSwapLookupService)(nil)
}

// helper kept here so the file's hex-only fixture imports are obvious.
var _ = hex.EncodeToString
