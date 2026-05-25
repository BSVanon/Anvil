package lookups

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// --- helpers ----------------------------------------------------------------

func newUHRPLookup(t *testing.T) *UHRPLookupService {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewUHRPLookupService(db)
}

// buildUHRPAdmitPayload constructs an OutputAdmittedByTopic carrying a real
// atomic BEEF that wraps a tx whose output #0 is a UHRP advertisement for
// the provided content hash + optional URL + content-type. Real signatures
// are not required — the lookup only parses the locking script.
func buildUHRPAdmitPayload(t *testing.T, contentHash, url, contentType string) *engine.OutputAdmittedByTopic {
	t.Helper()
	hashBytes, err := hex.DecodeString(contentHash)
	if err != nil || len(hashBytes) != 32 {
		t.Fatalf("invalid content hash %q (need 64 hex chars)", contentHash)
	}
	scriptBytes := []byte{0x00, 0x6a, byte(len(topics.UHRPProtocolID))}
	scriptBytes = append(scriptBytes, []byte(topics.UHRPProtocolID)...)
	scriptBytes = append(scriptBytes, byte(len(hashBytes)))
	scriptBytes = append(scriptBytes, hashBytes...)
	if url != "" {
		scriptBytes = append(scriptBytes, byte(len(url)))
		scriptBytes = append(scriptBytes, []byte(url)...)
	}
	if contentType != "" {
		scriptBytes = append(scriptBytes, byte(len(contentType)))
		scriptBytes = append(scriptBytes, []byte(contentType)...)
	}

	tx := transaction.NewTransaction()
	s := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &s, Satoshis: 0})

	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	txid := tx.TxID()
	atomicBytes, err := beef.AtomicBytes(txid)
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return &engine.OutputAdmittedByTopic{
		Topic:       topics.UHRPTopicName,
		OutputIndex: 0,
		AtomicBEEF:  atomicBytes,
	}
}

func mustOutpointFromPayload(t *testing.T, p *engine.OutputAdmittedByTopic) *transaction.Outpoint {
	t.Helper()
	_, txid, err := transaction.NewBeefFromAtomicBytes(p.AtomicBEEF)
	if err != nil {
		t.Fatalf("decode atomic beef: %v", err)
	}
	return &transaction.Outpoint{Txid: *txid, Index: p.OutputIndex}
}

func ctxBg() context.Context { return context.Background() }

const sampleHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const sampleHashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// --- tests ------------------------------------------------------------------

func TestUHRP_AdmitAndLookupByHash(t *testing.T) {
	s := newUHRPLookup(t)

	payload := buildUHRPAdmitPayload(t, sampleHashA, "https://example.com/a", "image/png")
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}

	q, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: sampleHashA})
	answer, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{
		Service: topics.UHRPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if answer.Type != lookup.AnswerTypeFormula {
		t.Fatalf("expected formula answer, got %s", answer.Type)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula, got %d", len(answer.Formulas))
	}
	want := mustOutpointFromPayload(t, payload)
	got := answer.Formulas[0].Outpoint
	if got == nil || !got.Equal(want) {
		t.Fatalf("formula outpoint mismatch: got %v, want %v", got, want)
	}
}

func TestUHRP_NonUHRPTopicIgnored(t *testing.T) {
	s := newUHRPLookup(t)
	payload := buildUHRPAdmitPayload(t, sampleHashA, "", "")
	payload.Topic = "tm_ordlock_listings"

	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{List: "all"})
	answer, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{
		Service: topics.UHRPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 formulas, got %d (non-UHRP topic should be ignored)", len(answer.Formulas))
	}
}

func TestUHRP_NonUHRPScriptDropped(t *testing.T) {
	s := newUHRPLookup(t)
	// Build a tx whose output is OP_FALSE OP_RETURN "FOO" + 32 bytes — not
	// the UHRP protocol id.
	scriptBytes := []byte{0x00, 0x6a, 0x03, 'F', 'O', 'O', 32}
	scriptBytes = append(scriptBytes, make([]byte, 32)...)
	tx := transaction.NewTransaction()
	sc := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &sc, Satoshis: 0})
	beef, _ := transaction.NewBeefFromTransaction(tx)
	atomicBytes, _ := beef.AtomicBytes(tx.TxID())

	payload := &engine.OutputAdmittedByTopic{
		Topic:       topics.UHRPTopicName,
		OutputIndex: 0,
		AtomicBEEF:  atomicBytes,
	}
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit non-UHRP script: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{List: "all"})
	answer, _ := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 formulas for non-UHRP script, got %d", len(answer.Formulas))
	}
}

func TestUHRP_ListAllAndHashes(t *testing.T) {
	s := newUHRPLookup(t)

	pA1 := buildUHRPAdmitPayload(t, sampleHashA, "https://a1", "")
	pA2 := buildUHRPAdmitPayload(t, sampleHashA, "https://a2", "")
	pB := buildUHRPAdmitPayload(t, sampleHashB, "https://b1", "")
	for _, p := range []*engine.OutputAdmittedByTopic{pA1, pA2, pB} {
		if err := s.OutputAdmittedByTopic(ctxBg(), p); err != nil {
			t.Fatalf("admit: %v", err)
		}
	}

	// list=all
	qAll, _ := json.Marshal(topics.UHRPLookupQuery{List: "all"})
	answerAll, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: qAll})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(answerAll.Formulas) != 3 {
		t.Fatalf("list all expected 3 formulas, got %d", len(answerAll.Formulas))
	}

	// list=hashes
	qHashes, _ := json.Marshal(topics.UHRPLookupQuery{List: "hashes"})
	answerH, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: qHashes})
	if err != nil {
		t.Fatalf("list hashes: %v", err)
	}
	if answerH.Type != lookup.AnswerTypeFreeform {
		t.Fatalf("expected freeform, got %s", answerH.Type)
	}
	counts, ok := answerH.Result.(map[string]int)
	if !ok {
		t.Fatalf("expected map[string]int result, got %T", answerH.Result)
	}
	if counts[strings.ToLower(sampleHashA)] != 2 || counts[strings.ToLower(sampleHashB)] != 1 {
		t.Fatalf("counts mismatch: %+v", counts)
	}
}

func TestUHRP_OutputSpentRemovesEntry(t *testing.T) {
	s := newUHRPLookup(t)
	payload := buildUHRPAdmitPayload(t, sampleHashA, "", "")
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	spendPayload := &engine.OutputSpent{
		Outpoint: op,
		Topic:    topics.UHRPTopicName,
	}
	if err := s.OutputSpent(ctxBg(), spendPayload); err != nil {
		t.Fatalf("spend: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: sampleHashA})
	answer, _ := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 formulas after spend, got %d", len(answer.Formulas))
	}
}

func TestUHRP_OutputSpentWrongTopicIgnored(t *testing.T) {
	s := newUHRPLookup(t)
	payload := buildUHRPAdmitPayload(t, sampleHashA, "", "")
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	// Spend notification for a different topic should be a no-op.
	if err := s.OutputSpent(ctxBg(), &engine.OutputSpent{
		Outpoint: op,
		Topic:    "tm_ordlock_listings",
	}); err != nil {
		t.Fatalf("spend wrong-topic: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: sampleHashA})
	answer, _ := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected entry still present after wrong-topic spend, got %d", len(answer.Formulas))
	}
}

func TestUHRP_OutputEvictedRemovesEntry(t *testing.T) {
	s := newUHRPLookup(t)
	payload := buildUHRPAdmitPayload(t, sampleHashA, "", "")
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	if err := s.OutputEvicted(ctxBg(), op); err != nil {
		t.Fatalf("evict: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{List: "all"})
	answer, _ := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 after eviction, got %d", len(answer.Formulas))
	}
}

func TestUHRP_NoLongerRetainedInHistoryRemoves(t *testing.T) {
	s := newUHRPLookup(t)
	payload := buildUHRPAdmitPayload(t, sampleHashA, "", "")
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	if err := s.OutputNoLongerRetainedInHistory(ctxBg(), op, topics.UHRPTopicName); err != nil {
		t.Fatalf("no-longer-retained: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{List: "all"})
	answer, _ := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 after retain-loss, got %d", len(answer.Formulas))
	}
}

func TestUHRP_LookupQueryGuards(t *testing.T) {
	s := newUHRPLookup(t)

	if _, err := s.Lookup(ctxBg(), nil); err == nil {
		t.Fatalf("expected error for nil question")
	}
	if _, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: "ls_other"}); err == nil {
		t.Fatalf("expected error for wrong service")
	}
	if _, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName}); err == nil {
		t.Fatalf("expected error for missing content_hash + list")
	}
}

func TestUHRP_DocsAndMetaData(t *testing.T) {
	s := newUHRPLookup(t)
	if s.GetDocumentation() == "" {
		t.Fatalf("docs empty")
	}
	md := s.GetMetaData()
	if md == nil || md.Name != topics.UHRPLookupServiceName {
		t.Fatalf("metadata mismatch: %+v", md)
	}
}

func TestUHRP_CompileTimeInterfaceCheck(t *testing.T) {
	var _ engine.LookupService = (*UHRPLookupService)(nil)
}
