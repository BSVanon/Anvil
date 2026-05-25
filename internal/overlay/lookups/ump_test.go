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
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

// newUMPLookup mirrors newUHRPLookup — temp-dir LevelDB + fresh service.
func newUMPLookup(t *testing.T) *UMPLookupService {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewUMPLookupService(db)
}

// umpTestWallet returns a fresh CompletedProtoWallet for PushDrop
// fixture construction. Each call produces a unique key so distinct
// fixtures don't collide on PushDrop's lock-before pubkey.
func umpTestWallet(t *testing.T) wallet.Interface {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	return w
}

// buildUMPAdmitPayload constructs an OutputAdmittedByTopic with a real
// atomic BEEF wrapping a tx whose output #0 is a UMP token PushDrop
// with the supplied 11 protocol fields (no v3 detection).
func buildUMPAdmitPayload(t *testing.T, presentationHash, recoveryHash []byte) *engine.OutputAdmittedByTopic {
	t.Helper()
	w := umpTestWallet(t)
	fields := [][]byte{
		{0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06},
		presentationHash, recoveryHash,
		{0x09}, {0x0a}, {0x0b},
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		fields,
		wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      "admin user management token",
		},
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		false, // forSelf
		false, // includeSignature: false to keep field count == 11
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}

	tx := transaction.NewTransaction()
	scriptBytes := s.Bytes()
	out := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: 1})

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
		Topic:       topics.UMPTopicName,
		OutputIndex: 0,
		AtomicBEEF:  atomicBytes,
	}
}

// outpointFromUMPPayload extracts the outpoint of the admitted output.
// Used to verify lookup-by-outpoint and OutputSpent removal.
func outpointFromUMPPayload(t *testing.T, p *engine.OutputAdmittedByTopic) *transaction.Outpoint {
	t.Helper()
	_, txid, err := transaction.NewBeefFromAtomicBytes(p.AtomicBEEF)
	if err != nil {
		t.Fatalf("decode atomic beef: %v", err)
	}
	return &transaction.Outpoint{Txid: *txid, Index: p.OutputIndex}
}

func umpHashHex(b []byte) string { return hex.EncodeToString(b) }

// TestUMP_AdmitAndLookupByPresentationHash pins the SendBSV-Wallet
// happy-path: a UMP token gets admitted via OutputAdmittedByTopic, then
// a lookup keyed by presentationHash returns the outpoint. This is the
// load-bearing flow for returning-user same-passkey rehydrate from
// SENDBSV_USERS_TOPIC_REQUEST.md acceptance criterion #5.
func TestUMP_AdmitAndLookupByPresentationHash(t *testing.T) {
	ctx := context.Background()
	s := newUMPLookup(t)
	presH := make([]byte, 32)
	for i := range presH {
		presH[i] = 0xaa
	}
	recH := make([]byte, 32)
	for i := range recH {
		recH[i] = 0xbb
	}

	payload := buildUMPAdmitPayload(t, presH, recH)
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit: %v", err)
	}

	q, _ := json.Marshal(topics.UMPLookupQuery{PresentationHash: umpHashHex(presH)})
	answer, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("Lookup by presentationHash: %v", err)
	}
	if answer.Type != lookup.AnswerTypeFormula {
		t.Fatalf("expected formula answer, got %s", answer.Type)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula, got %d", len(answer.Formulas))
	}
	expected := outpointFromUMPPayload(t, payload)
	if answer.Formulas[0].Outpoint == nil || !answer.Formulas[0].Outpoint.Txid.IsEqual(&expected.Txid) {
		t.Fatalf("outpoint mismatch: want %s, got %+v", expected.String(), answer.Formulas[0].Outpoint)
	}
}

// TestUMP_LookupByRecoveryHash pins the lost-passkey-recovery path —
// SENDBSV_USERS_TOPIC_REQUEST.md's other primary UMP query shape.
func TestUMP_LookupByRecoveryHash(t *testing.T) {
	ctx := context.Background()
	s := newUMPLookup(t)
	presH := make([]byte, 32)
	for i := range presH {
		presH[i] = 0xc1
	}
	recH := make([]byte, 32)
	for i := range recH {
		recH[i] = 0xc2
	}

	if err := s.OutputAdmittedByTopic(ctx, buildUMPAdmitPayload(t, presH, recH)); err != nil {
		t.Fatalf("admit: %v", err)
	}

	q, _ := json.Marshal(topics.UMPLookupQuery{RecoveryHash: umpHashHex(recH)})
	answer, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("Lookup by recoveryHash: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula by recoveryHash, got %d", len(answer.Formulas))
	}
}

// TestUMP_LookupByOutpoint confirms the republish/health-check query
// works — exact-outpoint resolution.
func TestUMP_LookupByOutpoint(t *testing.T) {
	ctx := context.Background()
	s := newUMPLookup(t)
	payload := buildUMPAdmitPayload(t, make([]byte, 32), make([]byte, 32))
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := outpointFromUMPPayload(t, payload)

	q, _ := json.Marshal(topics.UMPLookupQuery{Outpoint: op.String()})
	answer, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("Lookup by outpoint: %v", err)
	}
	if len(answer.Formulas) != 1 || answer.Formulas[0].Outpoint == nil {
		t.Fatalf("expected 1 outpoint match, got %d (%+v)", len(answer.Formulas), answer.Formulas)
	}
}

// TestUMP_LookupMissingReturnsEmpty pins the canonical empty-result
// wire shape — must be an empty formula slice, not nil, not an error.
func TestUMP_LookupMissingReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	s := newUMPLookup(t)
	q, _ := json.Marshal(topics.UMPLookupQuery{
		PresentationHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	answer, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("Lookup missing: %v", err)
	}
	if answer.Type != lookup.AnswerTypeFormula {
		t.Fatalf("expected formula answer, got %s", answer.Type)
	}
	if answer.Formulas == nil {
		t.Fatal("Formulas must be empty slice not nil (canonical wire format)")
	}
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 formulas for missing hash, got %d", len(answer.Formulas))
	}
}

// TestUMP_OutputSpent_RemovesEntry pins that the canonical UMP rotation
// flow (spend old token, admit new one) drops the old entry from the
// index — required so subsequent lookups don't return stale outpoints.
func TestUMP_OutputSpent_RemovesEntry(t *testing.T) {
	ctx := context.Background()
	s := newUMPLookup(t)
	presH := make([]byte, 32)
	for i := range presH {
		presH[i] = 0xd1
	}
	payload := buildUMPAdmitPayload(t, presH, make([]byte, 32))
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := outpointFromUMPPayload(t, payload)

	if err := s.OutputSpent(ctx, &engine.OutputSpent{
		Topic:    topics.UMPTopicName,
		Outpoint: op,
	}); err != nil {
		t.Fatalf("OutputSpent: %v", err)
	}

	q, _ := json.Marshal(topics.UMPLookupQuery{PresentationHash: umpHashHex(presH)})
	answer, _ := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 formulas after spend, got %d", len(answer.Formulas))
	}
}

// TestUMP_NonUMPTopicIgnored confirms the engine fans every admission
// to every lookup service; non-UMP topics must be silently skipped
// (matches UMPLookupService.ts:18).
func TestUMP_NonUMPTopicIgnored(t *testing.T) {
	ctx := context.Background()
	s := newUMPLookup(t)
	// Build a payload with a UMP-shaped output but tagged as a different
	// topic. The lookup should ignore it entirely.
	payload := buildUMPAdmitPayload(t, make([]byte, 32), make([]byte, 32))
	payload.Topic = "tm_uhrp"
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit non-UMP: %v", err)
	}
	// Query should return nothing — the non-UMP admission was ignored.
	q, _ := json.Marshal(topics.UMPLookupQuery{PresentationHash: "00"})
	answer, _ := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if len(answer.Formulas) != 0 {
		t.Fatal("non-UMP admit should not have populated the index")
	}
}

// TestUMP_LookupRequiresQuerySelector pins the validation that at
// least one of presentationHash/recoveryHash/outpoint must be present.
func TestUMP_LookupRequiresQuerySelector(t *testing.T) {
	ctx := context.Background()
	s := newUMPLookup(t)
	q, _ := json.Marshal(topics.UMPLookupQuery{})
	_, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.UMPLookupServiceName,
		Query:   q,
	})
	if err == nil {
		t.Fatal("empty UMP query must surface a clear error")
	}
}
