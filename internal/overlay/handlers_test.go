package overlay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// mockAdmitAll always admits output 0.
type mockAdmitAll struct{}

func (m *mockAdmitAll) Admit(txData []byte, prev []AdmittedOutput) (*AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, err
	}
	outputs := make([]int, len(tx.Outputs))
	for i := range tx.Outputs {
		outputs[i] = i
	}
	return &AdmittanceInstructions{OutputsToAdmit: outputs}, nil
}
func (m *mockAdmitAll) GetDocumentation() string            { return "test" }
func (m *mockAdmitAll) GetMetadata() map[string]interface{} { return nil }

// mockAllLookup returns all outputs.
type mockAllLookup struct{ engine *Engine }

func (m *mockAllLookup) Lookup(query json.RawMessage) (*LookupAnswer, error) {
	outputs, _ := m.engine.GetOutputsByTopic("tm_test")
	return &LookupAnswer{Type: "output-list", Outputs: outputs}, nil
}
func (m *mockAllLookup) GetDocumentation() string            { return "test" }
func (m *mockAllLookup) GetMetadata() map[string]interface{} { return nil }

func noopCors(next http.HandlerFunc) http.HandlerFunc { return next }

func testEngine(t *testing.T) *Engine {
	t.Helper()
	dir, _ := os.MkdirTemp("", "anvil-handler-test-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := NewEngine(db, nil)
	e.RegisterTopic("tm_test", &mockAdmitAll{})
	e.RegisterLookup("ls_test", &mockAllLookup{engine: e}, []string{"tm_test"})
	return e
}

func buildMinimalTx() []byte {
	tx := transaction.NewTransaction()
	prevTxID, _ := chainhash.NewHashFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID: prevTxID, SourceTxOutIndex: 0, SequenceNumber: 0xffffffff,
	})
	ls, _ := script.NewFromHex("006a") // OP_FALSE OP_RETURN
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: ls})
	return tx.Bytes()
}

func TestHTTPSubmitAndQuery(t *testing.T) {
	e := testEngine(t)
	mux := http.NewServeMux()
	e.RegisterHTTPHandlers(mux, noopCors)

	// --- Submit via JSON ---
	txBytes := buildMinimalTx()
	body, _ := json.Marshal(TaggedBEEF{
		BEEF:   txBytes,
		Topics: []string{"tm_test"},
	})

	req := httptest.NewRequest("POST", "/overlay/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("submit: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var steak STEAK
	json.Unmarshal(w.Body.Bytes(), &steak)
	if _, ok := steak["tm_test"]; !ok {
		t.Fatal("STEAK missing tm_test")
	}
	t.Logf("Submit OK: %s", w.Body.String())

	// --- Query via lookup ---
	queryBody, _ := json.Marshal(LookupQuestion{
		Service: "ls_test",
		Query:   json.RawMessage(`{}`),
	})

	req2 := httptest.NewRequest("POST", "/overlay/query", bytes.NewReader(queryBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("query: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var answer LookupAnswer
	json.Unmarshal(w2.Body.Bytes(), &answer)
	if answer.Type != "output-list" {
		t.Fatalf("expected output-list, got %s", answer.Type)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(answer.Outputs))
	}
	t.Logf("Query OK: %d outputs", len(answer.Outputs))
}

func TestHTTPSubmitBinary(t *testing.T) {
	e := testEngine(t)
	mux := http.NewServeMux()
	e.RegisterHTTPHandlers(mux, noopCors)

	txBytes := buildMinimalTx()
	req := httptest.NewRequest("POST", "/overlay/submit", bytes.NewReader(txBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", `["tm_test"]`)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("binary submit: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	t.Logf("Binary submit OK: %s", w.Body.String())
}

func TestHTTPSubmitAtomicBEEF(t *testing.T) {
	e := testEngine(t)
	mux := http.NewServeMux()
	e.RegisterHTTPHandlers(mux, noopCors)

	// Build a tx with proper parent chain so BEEF() works
	parent := transaction.NewTransaction()
	parent.Version = 1
	ls, _ := script.NewFromHex("006a04deadbeef")
	parent.AddOutput(&transaction.TransactionOutput{Satoshis: 100, LockingScript: ls})

	child := transaction.NewTransaction()
	child.AddInputFrom(parent.TxID().String(), 0, ls.String(), 100, nil)
	child.Inputs[0].SourceTransaction = parent
	ls2, _ := script.NewFromHex("006a0455484850")
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: ls2})

	beef, err := child.BEEF()
	if err != nil {
		t.Fatalf("BEEF(): %v", err)
	}

	// Verify it starts with BEEF magic bytes
	if len(beef) < 4 || beef[0] != 0x01 || beef[1] != 0x00 || beef[2] != 0xBE || beef[3] != 0xEF {
		t.Fatalf("not valid BEEF: %x", beef[:4])
	}

	// Submit as Babbage-style binary with X-Topics header
	req := httptest.NewRequest("POST", "/overlay/submit", bytes.NewReader(beef))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", `["tm_test"]`)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("BEEF submit: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var steak STEAK
	json.Unmarshal(w.Body.Bytes(), &steak)
	if _, ok := steak["tm_test"]; !ok {
		t.Fatal("STEAK missing tm_test after BEEF submit")
	}
	if len(steak["tm_test"].OutputsToAdmit) != 1 {
		t.Fatalf("expected 1 admitted output, got %d", len(steak["tm_test"].OutputsToAdmit))
	}
	t.Logf("Atomic BEEF submit OK: txid parsed, output admitted ✓")
}

func TestHTTPListTopicsAndServices(t *testing.T) {
	e := testEngine(t)
	mux := http.NewServeMux()
	e.RegisterHTTPHandlers(mux, noopCors)

	// List topics
	req := httptest.NewRequest("GET", "/overlay/topics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list topics: expected 200, got %d", w.Code)
	}
	t.Logf("Topics: %s", w.Body.String())

	// List services
	req2 := httptest.NewRequest("GET", "/overlay/services", nil)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("list services: expected 200, got %d", w2.Code)
	}
	t.Logf("Services: %s", w2.Body.String())
}
