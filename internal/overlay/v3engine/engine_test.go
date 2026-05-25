package v3engine

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// newTestEngine wires every Anvil canonical piece into a fresh engine
// backed by tmp-dir LevelDB instances + an Anvil header store with PoW
// validation disabled. The header store stays at genesis height, which
// is enough because the test transactions we submit don't carry merkle
// proofs — they're unmined, so the SPV verifier exercises only the
// no-merkle-path branch.
func newTestEngine(t *testing.T) (*engine.Engine, *leveldb.DB) {
	t.Helper()
	root := t.TempDir()

	storageDir := filepath.Join(root, "storage-ldb")
	storageDB, err := leveldb.OpenFile(storageDir, nil)
	if err != nil {
		t.Fatalf("open storage db: %v", err)
	}
	t.Cleanup(func() { _ = storageDB.Close() })

	lookupDir := filepath.Join(root, "lookup-ldb")
	lookupDB, err := leveldb.OpenFile(lookupDir, nil)
	if err != nil {
		t.Fatalf("open lookup db: %v", err)
	}
	t.Cleanup(func() { _ = lookupDB.Close() })

	hdrDir := filepath.Join(root, "headers")
	hdrStore, err := headers.NewTestStore(hdrDir)
	if err != nil {
		t.Fatalf("open headers store: %v", err)
	}
	t.Cleanup(func() { _ = hdrStore.Close() })

	eng, err := New(&Config{
		Storage:      anvilstorage.New(storageDB),
		HeadersStore: hdrStore,
		LookupDB:     lookupDB,
		HostingURL:   "https://anvil.test",
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	return eng, lookupDB
}

// buildUHRPTaggedBEEF assembles a TaggedBEEF carrying a one-output tx
// whose locking script is a real BRC-26 UHRP advertisement for the
// given content hash. The atomic-BEEF form is what engine.Submit reads.
func buildUHRPTaggedBEEF(t *testing.T, contentHashHex, url, contentType string) overlay.TaggedBEEF {
	t.Helper()
	hashBytes, err := hex.DecodeString(contentHashHex)
	if err != nil || len(hashBytes) != 32 {
		t.Fatalf("bad hash hex: %v", err)
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
	atomicBytes, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return overlay.TaggedBEEF{
		Beef:   atomicBytes,
		Topics: []string{topics.UHRPTopicName},
	}
}

// TestEngine_SubmitAndLookupUHRP is the W-5 phase A end-to-end proof
// point: a real UHRP-bearing tx routed through engine.Submit reaches
// both the topic adapter and the lookup service, and engine.Lookup then
// resolves the lookup's formula via the storage adapter back to a fully
// hydrated OutputListItem. This exercises the full storage + topic +
// lookup wiring in one shot.
func TestEngine_SubmitAndLookupUHRP(t *testing.T) {
	eng, _ := newTestEngine(t)

	const hashHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "https://example.test/a", "image/png")

	steak, err := eng.Submit(context.Background(), tagged, engine.SubmitModeHistorical, nil)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if steak == nil {
		t.Fatalf("nil steak")
	}
	if inst, ok := steak[topics.UHRPTopicName]; !ok || inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected UHRP admit output 0, got %+v", inst)
	}

	q, err := json.Marshal(topics.UHRPLookupQuery{ContentHash: hashHex})
	if err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	answer, err := eng.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.UHRPLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if answer.Type != lookup.AnswerTypeOutputList {
		t.Fatalf("expected output-list (engine hydrates formulas), got %s", answer.Type)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 hydrated output, got %d", len(answer.Outputs))
	}
	if len(answer.Outputs[0].Beef) == 0 {
		t.Fatalf("expected BEEF hydrated by engine, got empty")
	}
}

// TestEngine_ListsRegisteredServices verifies the engine surfaces both
// the four topic managers and the four lookup services that the wiring
// registers, with the canonical names. This is the smoke test for
// /listTopicManagers + /listLookupServiceProviders before they have
// HTTP handlers.
func TestEngine_ListsRegisteredServices(t *testing.T) {
	eng, _ := newTestEngine(t)

	wantTopics := []string{
		topics.UHRPTopicName,
		topics.DEXSwapTopicName,
		topics.OrdLockTopicName,
		topics.OrdLockBuyTopicName,
	}
	tms := eng.ListTopicManagers()
	for _, name := range wantTopics {
		md, ok := tms[name]
		if !ok || md == nil {
			t.Fatalf("missing topic manager %q in registry: keys=%v", name, mapKeys(tms))
		}
		if !strings.EqualFold(md.Name, name) {
			t.Fatalf("topic %q metadata Name=%q mismatch", name, md.Name)
		}
	}

	wantServices := []string{
		topics.UHRPLookupServiceName,
		topics.DEXSwapLookupServiceName,
		topics.OrdLockLookupServiceName,
		topics.OrdLockBuyLookupServiceName,
	}
	lss := eng.ListLookupServiceProviders()
	for _, name := range wantServices {
		md, ok := lss[name]
		if !ok || md == nil {
			t.Fatalf("missing lookup service %q in registry: keys=%v", name, mapKeys(lss))
		}
		if !strings.EqualFold(md.Name, name) {
			t.Fatalf("service %q metadata Name=%q mismatch", name, md.Name)
		}
	}
}

// TestNew_RejectsNilConfig asserts the constructor's loud-fail guards
// fire on missing required inputs so caller boot-time mistakes show up
// at startup rather than as nil-deref panics on first /submit.
func TestNew_RejectsNilConfig(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatalf("expected error for nil config")
	}
	if _, err := New(&Config{}); err == nil {
		t.Fatalf("expected error for empty config")
	}
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
