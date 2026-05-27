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
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

var kvLookupProtocol = wallet.Protocol{
	SecurityLevel: wallet.SecurityLevelEveryApp,
	Protocol:      "sendbsv settings",
}

func newKVStoreLookup(t *testing.T) *KVStoreLookupService {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewKVStoreLookupService(db)
}

// buildKVAdmitPayload builds an OutputAdmittedByTopic whose atomic BEEF
// wraps a tx with a single KVStore PushDrop output. The appended
// signature does not need to verify here — the lookup-side index path
// (ParseKVStoreOutput) only decodes shape; admission verifies signatures.
func buildKVAdmitPayload(t *testing.T, controllerPub []byte, key, value string, tags []string, tagged bool) *engine.OutputAdmittedByTopic {
	t.Helper()
	protoJSON, err := json.Marshal(&kvLookupProtocol)
	if err != nil {
		t.Fatalf("marshal protocol: %v", err)
	}
	fields := [][]byte{protoJSON, []byte(key), []byte(value), controllerPub}
	if tagged {
		tagsJSON, _ := json.Marshal(tags)
		fields = append(fields, tagsJSON)
	}
	lockPriv, _ := ec.NewPrivateKey()
	lockWallet, _ := wallet.NewCompletedProtoWallet(lockPriv)
	pd := &pushdrop.PushDrop{Wallet: lockWallet}
	s, err := pd.Lock(
		context.Background(),
		fields,
		kvLookupProtocol, key,
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		false, true, pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	tx := transaction.NewTransaction()
	sb := s.Bytes()
	out := script.Script(sb)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: 1})

	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	atomicBytes, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return &engine.OutputAdmittedByTopic{
		Topic:       topics.KVStoreTopicName,
		OutputIndex: 0,
		AtomicBEEF:  atomicBytes,
	}
}

func kvPubHex(t *testing.T) (priv *ec.PrivateKey, pub []byte) {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	return priv, priv.PubKey().Compressed()
}

func kvLookup(t *testing.T, s *KVStoreLookupService, q topics.KVStoreLookupQuery) *lookup.LookupAnswer {
	t.Helper()
	body, _ := json.Marshal(q)
	ans, err := s.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.KVStoreLookupServiceName,
		Query:   body,
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return ans
}

// TestKVStore_AdmitAndLookupByKey pins the primary path: admit a token,
// query by key, get the outpoint back.
func TestKVStore_AdmitAndLookupByKey(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pub := kvPubHex(t)
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pub, "fiat-currency", "GBP", nil, false)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	ans := kvLookup(t, s, topics.KVStoreLookupQuery{Key: "fiat-currency"})
	if ans.Type != lookup.AnswerTypeFormula || len(ans.Formulas) != 1 {
		t.Fatalf("expected 1 formula, got type=%s n=%d", ans.Type, len(ans.Formulas))
	}
}

// TestKVStore_LookupByController returns every key for a controller.
func TestKVStore_LookupByController(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pub := kvPubHex(t)
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pub, "fiat-currency", "GBP", nil, false)); err != nil {
		t.Fatalf("admit 1: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pub, "cold-address", "addr", nil, false)); err != nil {
		t.Fatalf("admit 2: %v", err)
	}
	ctrlHex := hex.EncodeToString(pub)
	ans := kvLookup(t, s, topics.KVStoreLookupQuery{Controller: ctrlHex})
	if len(ans.Formulas) != 2 {
		t.Fatalf("expected 2 formulas for controller, got %d", len(ans.Formulas))
	}
}

// TestKVStore_LookupByProtocolID filters on the [level, name] array.
func TestKVStore_LookupByProtocolID(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pub := kvPubHex(t)
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pub, "k", "v", nil, false)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	ans := kvLookup(t, s, topics.KVStoreLookupQuery{ProtocolID: json.RawMessage(`[1,"sendbsv settings"]`)})
	if len(ans.Formulas) != 1 {
		t.Fatalf("expected 1 formula by protocolID, got %d", len(ans.Formulas))
	}
	// A non-matching protocolID returns nothing.
	ans = kvLookup(t, s, topics.KVStoreLookupQuery{ProtocolID: json.RawMessage(`[2,"other"]`)})
	if len(ans.Formulas) != 0 {
		t.Fatalf("expected 0 formulas for non-matching protocolID, got %d", len(ans.Formulas))
	}
}

// TestKVStore_LookupByTags exercises both tagQueryMode all + any.
func TestKVStore_LookupByTags(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pub := kvPubHex(t)
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pub, "k1", "v1", []string{"prefs", "display"}, true)); err != nil {
		t.Fatalf("admit 1: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pub, "k2", "v2", []string{"prefs"}, true)); err != nil {
		t.Fatalf("admit 2: %v", err)
	}

	// "all" with [prefs, display] matches only k1.
	ans := kvLookup(t, s, topics.KVStoreLookupQuery{Tags: []string{"prefs", "display"}, TagQueryMode: "all"})
	if len(ans.Formulas) != 1 {
		t.Fatalf("tagQueryMode=all expected 1, got %d", len(ans.Formulas))
	}
	// "any" with [display] matches only k1.
	ans = kvLookup(t, s, topics.KVStoreLookupQuery{Tags: []string{"display"}, TagQueryMode: "any"})
	if len(ans.Formulas) != 1 {
		t.Fatalf("tagQueryMode=any [display] expected 1, got %d", len(ans.Formulas))
	}
	// "any" with [prefs] matches both.
	ans = kvLookup(t, s, topics.KVStoreLookupQuery{Tags: []string{"prefs"}, TagQueryMode: "any"})
	if len(ans.Formulas) != 2 {
		t.Fatalf("tagQueryMode=any [prefs] expected 2, got %d", len(ans.Formulas))
	}
}

// TestKVStore_CombinedFiltersANDNarrow confirms multiple selectors
// intersect (controller + key).
func TestKVStore_CombinedFiltersANDNarrow(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pubA := kvPubHex(t)
	_, pubB := kvPubHex(t)
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pubA, "fiat-currency", "GBP", nil, false)); err != nil {
		t.Fatalf("admit A: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pubB, "fiat-currency", "USD", nil, false)); err != nil {
		t.Fatalf("admit B: %v", err)
	}
	// key alone → 2; key + controllerA → 1.
	ans := kvLookup(t, s, topics.KVStoreLookupQuery{Key: "fiat-currency"})
	if len(ans.Formulas) != 2 {
		t.Fatalf("key alone expected 2, got %d", len(ans.Formulas))
	}
	ans = kvLookup(t, s, topics.KVStoreLookupQuery{Key: "fiat-currency", Controller: hex.EncodeToString(pubA)})
	if len(ans.Formulas) != 1 {
		t.Fatalf("key+controllerA expected 1, got %d", len(ans.Formulas))
	}
}

// TestKVStore_LimitAndSkip pins pagination over a multi-record set.
func TestKVStore_LimitAndSkip(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pub := kvPubHex(t)
	for i := 0; i < 5; i++ {
		key := "k" + string(rune('0'+i))
		if err := s.OutputAdmittedByTopic(ctx, buildKVAdmitPayload(t, pub, key, "v", nil, false)); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	ans := kvLookup(t, s, topics.KVStoreLookupQuery{Controller: hex.EncodeToString(pub), Limit: 2})
	if len(ans.Formulas) != 2 {
		t.Fatalf("limit=2 expected 2, got %d", len(ans.Formulas))
	}
	ans = kvLookup(t, s, topics.KVStoreLookupQuery{Controller: hex.EncodeToString(pub), Limit: 2, Skip: 4})
	if len(ans.Formulas) != 1 {
		t.Fatalf("limit=2 skip=4 over 5 records expected 1, got %d", len(ans.Formulas))
	}
}

// TestKVStore_OutputSpentRemovesEntry pins that spending a token drops
// it from all indexes.
func TestKVStore_OutputSpentRemovesEntry(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pub := kvPubHex(t)
	payload := buildKVAdmitPayload(t, pub, "k", "v", []string{"prefs"}, true)
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	_, txid, err := transaction.NewBeefFromAtomicBytes(payload.AtomicBEEF)
	if err != nil {
		t.Fatalf("decode beef: %v", err)
	}
	op := &transaction.Outpoint{Txid: *txid, Index: 0}
	if err := s.OutputSpent(ctx, &engine.OutputSpent{Topic: topics.KVStoreTopicName, Outpoint: op}); err != nil {
		t.Fatalf("OutputSpent: %v", err)
	}
	// All index paths now empty.
	if ans := kvLookup(t, s, topics.KVStoreLookupQuery{Key: "k"}); len(ans.Formulas) != 0 {
		t.Fatalf("expected 0 by key after spend, got %d", len(ans.Formulas))
	}
	if ans := kvLookup(t, s, topics.KVStoreLookupQuery{Tags: []string{"prefs"}}); len(ans.Formulas) != 0 {
		t.Fatalf("expected 0 by tag after spend, got %d", len(ans.Formulas))
	}
}

// TestKVStore_LookupRequiresSelector pins the canonical
// validateQuerySelectors error.
func TestKVStore_LookupRequiresSelector(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	body, _ := json.Marshal(topics.KVStoreLookupQuery{})
	if _, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.KVStoreLookupServiceName,
		Query:   body,
	}); err == nil {
		t.Fatal("empty KVStore query must surface a clear error")
	}
}

// TestKVStore_NonKVStoreTopicIgnored confirms the admit fan-out filter.
func TestKVStore_NonKVStoreTopicIgnored(t *testing.T) {
	ctx := context.Background()
	s := newKVStoreLookup(t)
	_, pub := kvPubHex(t)
	payload := buildKVAdmitPayload(t, pub, "k", "v", nil, false)
	payload.Topic = "tm_uhrp"
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit non-kvstore: %v", err)
	}
	if ans := kvLookup(t, s, topics.KVStoreLookupQuery{Key: "k"}); len(ans.Formulas) != 0 {
		t.Fatal("non-KVStore admit should not populate the index")
	}
}
