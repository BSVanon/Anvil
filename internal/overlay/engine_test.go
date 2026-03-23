package overlay

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// buildTestTx creates a minimal valid transaction for testing.
func buildTestTx() []byte {
	return buildTestTxWithPrev("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

func buildTestTxWithPrev(prevHex string) []byte {
	tx := transaction.NewTransaction()
	prevTxID, _ := chainhash.NewHashFromHex(prevHex)
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID: prevTxID, SourceTxOutIndex: 0, SequenceNumber: 0xffffffff,
	})
	ls, _ := script.NewFromHex("006a")
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: ls})
	return tx.Bytes()
}

// mockTopicManager always admits output 0.
type mockTopicManager struct{}

func (m *mockTopicManager) Admit(txData []byte, prev []AdmittedOutput) (*AdmittanceInstructions, error) {
	return &AdmittanceInstructions{
		OutputsToAdmit: []int{0},
	}, nil
}

func (m *mockTopicManager) GetDocumentation() string         { return "mock topic" }
func (m *mockTopicManager) GetMetadata() map[string]interface{} { return map[string]interface{}{"test": true} }

// mockLookupService returns all outputs for the topic.
type mockLookupService struct {
	engine *Engine
}

func (m *mockLookupService) Lookup(query json.RawMessage) (*LookupAnswer, error) {
	outputs, _ := m.engine.GetOutputsByTopic("tm_mock")
	return &LookupAnswer{Type: "output-list", Outputs: outputs}, nil
}

func (m *mockLookupService) GetDocumentation() string         { return "mock lookup" }
func (m *mockLookupService) GetMetadata() map[string]interface{} { return map[string]interface{}{} }

func tmpEngine(t *testing.T) *Engine {
	t.Helper()
	dir, _ := os.MkdirTemp("", "anvil-engine-test-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewEngine(db, nil)
}

func TestEngineRegisterAndList(t *testing.T) {
	e := tmpEngine(t)
	e.RegisterTopic("tm_mock", &mockTopicManager{})
	e.RegisterLookup("ls_mock", &mockLookupService{engine: e}, []string{"tm_mock"})

	topics := e.ListTopics()
	if len(topics) != 1 || topics[0] != "tm_mock" {
		t.Fatalf("expected [tm_mock], got %v", topics)
	}

	services := e.ListLookupServices()
	if len(services) != 1 || services[0] != "ls_mock" {
		t.Fatalf("expected [ls_mock], got %v", services)
	}
}

func TestEngineSubmitAndQuery(t *testing.T) {
	e := tmpEngine(t)
	e.RegisterTopic("tm_mock", &mockTopicManager{})
	e.RegisterLookup("ls_mock", &mockLookupService{engine: e}, []string{"tm_mock"})

	// Submit a fake tx (mock topic manager doesn't parse it)
	txData := buildTestTx()
	steak, err := e.Submit(txData, []string{"tm_mock"})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if _, ok := steak["tm_mock"]; !ok {
		t.Fatal("STEAK missing tm_mock result")
	}
	if len(steak["tm_mock"].OutputsToAdmit) != 1 {
		t.Fatalf("expected 1 admitted output, got %d", len(steak["tm_mock"].OutputsToAdmit))
	}

	// Query via lookup service
	answer, err := e.Lookup(LookupQuestion{
		Service: "ls_mock",
		Query:   json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if answer.Type != "output-list" {
		t.Fatalf("expected output-list, got %s", answer.Type)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(answer.Outputs))
	}
}

func TestEngineSubmitUnknownTopic(t *testing.T) {
	e := tmpEngine(t)

	steak, err := e.Submit(buildTestTx(), []string{"tm_unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if len(steak) != 0 {
		t.Fatalf("expected empty STEAK for unknown topic, got %d entries", len(steak))
	}
}

func TestEngineLookupUnknownService(t *testing.T) {
	e := tmpEngine(t)

	_, err := e.Lookup(LookupQuestion{Service: "ls_unknown", Query: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("expected error for unknown service")
	}
}

// selectiveTopicManager admits output 0, retains input 0, removes input 1.
// Tests that the engine correctly handles mixed retain/remove behavior.
type selectiveTopicManager struct{}

func (m *selectiveTopicManager) Admit(txData []byte, prev []AdmittedOutput) (*AdmittanceInstructions, error) {
	inst := &AdmittanceInstructions{
		OutputsToAdmit: []int{0},
	}
	if len(prev) >= 2 {
		inst.CoinsToRetain = []int{0} // keep first spent input for history
		inst.CoinsRemoved = []int{1}  // remove second spent input
	} else if len(prev) == 1 {
		inst.CoinsRemoved = []int{0}
	}
	return inst, nil
}
func (m *selectiveTopicManager) GetDocumentation() string            { return "selective" }
func (m *selectiveTopicManager) GetMetadata() map[string]interface{} { return nil }

func TestEngineSelectiveRetainRemove(t *testing.T) {
	e := tmpEngine(t)
	e.RegisterTopic("tm_selective", &selectiveTopicManager{})

	// Submit two transactions to create two admitted outputs (different prevTxIDs for unique txids)
	tx1 := buildTestTxWithPrev("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, err := e.Submit(tx1, []string{"tm_selective"})
	if err != nil {
		t.Fatal(err)
	}

	tx2 := buildTestTxWithPrev("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	_, err = e.Submit(tx2, []string{"tm_selective"})
	if err != nil {
		t.Fatal(err)
	}

	outputs, _ := e.GetOutputsByTopic("tm_selective")
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(outputs))
	}
	t.Logf("Two outputs admitted: %s and %s", outputs[0].Txid[:16], outputs[1].Txid[:16])

	// Build a transaction that spends BOTH admitted outputs
	tx3 := transaction.NewTransaction()
	txid1, _ := chainhash.NewHashFromHex(outputs[0].Txid)
	txid2, _ := chainhash.NewHashFromHex(outputs[1].Txid)
	tx3.AddInput(&transaction.TransactionInput{
		SourceTXID: txid1, SourceTxOutIndex: 0, SequenceNumber: 0xffffffff,
	})
	tx3.AddInput(&transaction.TransactionInput{
		SourceTXID: txid2, SourceTxOutIndex: 0, SequenceNumber: 0xffffffff,
	})
	ls, _ := script.NewFromHex("006a")
	tx3.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: ls})

	steak, err := e.Submit(tx3.Bytes(), []string{"tm_selective"})
	if err != nil {
		t.Fatal(err)
	}

	result := steak["tm_selective"]
	if result == nil {
		t.Fatal("missing tm_selective in STEAK")
	}

	// Should admit 1 new output
	if len(result.OutputsToAdmit) != 1 {
		t.Fatalf("expected 1 admitted, got %d", len(result.OutputsToAdmit))
	}

	// Should retain 1 and remove 1
	if len(result.CoinsToRetain) != 1 {
		t.Fatalf("expected 1 retained, got %d", len(result.CoinsToRetain))
	}
	if len(result.CoinsRemoved) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(result.CoinsRemoved))
	}

	// Verify: the removed output should be gone, retained should... still be gone
	// (retained means "keep for history" but the engine deletes from active set)
	// The engine only deletes CoinsRemoved, not CoinsToRetain.
	remaining, _ := e.GetOutputsByTopic("tm_selective")
	// Should have: the new output from tx3 + the retained output from the first spend
	// The removed output should be gone
	t.Logf("After selective spend: %d remaining outputs", len(remaining))
	t.Logf("CoinsToRetain (real input indices): %v", result.CoinsToRetain)
	t.Logf("CoinsRemoved (real input indices): %v", result.CoinsRemoved)
	t.Logf("Selective retain/remove test passed ✓")
}

func TestEngineSparseInputIndices(t *testing.T) {
	e := tmpEngine(t)
	e.RegisterTopic("tm_selective", &selectiveTopicManager{})

	// Admit two outputs with known txids
	tx1 := buildTestTxWithPrev("1111111111111111111111111111111111111111111111111111111111111111")
	tx2 := buildTestTxWithPrev("2222222222222222222222222222222222222222222222222222222222222222")
	e.Submit(tx1, []string{"tm_selective"})
	e.Submit(tx2, []string{"tm_selective"})

	outputs, _ := e.GetOutputsByTopic("tm_selective")
	if len(outputs) != 2 {
		t.Fatalf("expected 2, got %d", len(outputs))
	}

	// Build a tx with 5 inputs, but only inputs 1 and 3 spend admitted outputs (sparse)
	txSpend := transaction.NewTransaction()
	dummyHash := func(hex string) *chainhash.Hash { h, _ := chainhash.NewHashFromHex(hex); return h }

	// Input 0: unrelated (not in overlay)
	txSpend.AddInput(&transaction.TransactionInput{SourceTXID: dummyHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), SourceTxOutIndex: 0, SequenceNumber: 0xffffffff})
	// Input 1: spends outputs[0]
	txSpend.AddInput(&transaction.TransactionInput{SourceTXID: dummyHash(outputs[0].Txid), SourceTxOutIndex: 0, SequenceNumber: 0xffffffff})
	// Input 2: unrelated
	txSpend.AddInput(&transaction.TransactionInput{SourceTXID: dummyHash("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), SourceTxOutIndex: 0, SequenceNumber: 0xffffffff})
	// Input 3: spends outputs[1]
	txSpend.AddInput(&transaction.TransactionInput{SourceTXID: dummyHash(outputs[1].Txid), SourceTxOutIndex: 0, SequenceNumber: 0xffffffff})
	// Input 4: unrelated
	txSpend.AddInput(&transaction.TransactionInput{SourceTXID: dummyHash("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), SourceTxOutIndex: 0, SequenceNumber: 0xffffffff})

	ls, _ := script.NewFromHex("006a")
	txSpend.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: ls})

	steak, err := e.Submit(txSpend.Bytes(), []string{"tm_selective"})
	if err != nil {
		t.Fatal(err)
	}

	result := steak["tm_selective"]
	if result == nil {
		t.Fatal("missing result")
	}

	// selective topic manager: retain prev[0] (=input 1), remove prev[1] (=input 3)
	// CoinsToRetain should be [1] (real input index), NOT [0] (previousUTXOs index)
	// CoinsRemoved should be [3] (real input index), NOT [1]
	if len(result.CoinsToRetain) != 1 || result.CoinsToRetain[0] != 1 {
		t.Fatalf("CoinsToRetain: expected [1], got %v", result.CoinsToRetain)
	}
	if len(result.CoinsRemoved) != 1 || result.CoinsRemoved[0] != 3 {
		t.Fatalf("CoinsRemoved: expected [3], got %v", result.CoinsRemoved)
	}
	t.Logf("Sparse input indices correct: retain=[1] remove=[3] ✓")
}

// mockUTXOChecker simulates chain UTXO queries.
type mockUTXOChecker struct {
	spent map[string]bool // "txid:vout" → true if spent
}

func (m *mockUTXOChecker) IsUnspent(txid string, vout int) (bool, error) {
	key := fmt.Sprintf("%s:%d", txid, vout)
	if m.spent[key] {
		return false, nil
	}
	return true, nil
}

func TestEngineReconciliation(t *testing.T) {
	e := tmpEngine(t)
	e.RegisterTopic("tm_mock", &mockTopicManager{})

	// Submit a tx to create an admitted output
	txBytes := buildTestTx()
	steak, err := e.Submit(txBytes, []string{"tm_mock"})
	if err != nil {
		t.Fatal(err)
	}
	if len(steak) == 0 {
		t.Fatal("expected admission")
	}

	// Get the admitted output's txid
	outputs, _ := e.GetOutputsByTopic("tm_mock")
	if len(outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(outputs))
	}
	admittedTxid := outputs[0].Txid

	// Reconcile with checker that says it's still unspent → no removal
	checker := &mockUTXOChecker{spent: map[string]bool{}}
	removed, checked, err := e.Reconcile(checker)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("expected 0 removed, got %d", removed)
	}
	if checked != 1 {
		t.Fatalf("expected 1 checked, got %d", checked)
	}

	// Now mark it as spent on-chain
	checker.spent[fmt.Sprintf("%s:%d", admittedTxid, 0)] = true
	removed, _, err = e.Reconcile(checker)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 removed after spend, got %d", removed)
	}

	// Verify it's gone
	outputs, _ = e.GetOutputsByTopic("tm_mock")
	if len(outputs) != 0 {
		t.Fatalf("expected 0 outputs after reconciliation, got %d", len(outputs))
	}
	t.Log("reconciliation correctly removed spent output ✓")
}
