package topics

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// TestUHRPEndToEnd proves the full lifecycle:
// 1. Build a UHRP advertisement transaction
// 2. Submit to engine → admitted with metadata
// 3. Lookup by content hash → found
// 4. Build a spending transaction that consumes the UHRP UTXO
// 5. Submit the spend → previous output removed
// 6. Lookup by content hash → not found (superseded)
func TestUHRPEndToEnd(t *testing.T) {
	// Set up engine with UHRP topic + lookup
	dir, _ := os.MkdirTemp("", "anvil-uhrp-e2e-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	engine := overlay.NewEngine(db, nil)
	engine.RegisterTopic(UHRPTopicName, NewUHRPTopicManager())
	engine.RegisterLookup(UHRPLookupServiceName, NewUHRPLookupService(engine), []string{UHRPTopicName})

	// --- Step 1: Build a UHRP advertisement transaction ---
	contentHash := HashContent([]byte("<html>Hello World</html>"))
	uhrpScript, err := BuildUHRPScript(contentHash, "https://anvil.sendbsv.com/content/abc123_0", "text/html")
	if err != nil {
		t.Fatal(err)
	}

	tx1 := transaction.NewTransaction()
	// Add a dummy input (coinbase-like for testing)
	dummyPrevTxid, _ := chainhash.NewHashFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx1.AddInput(&transaction.TransactionInput{
		SourceTXID:       dummyPrevTxid,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	// Add UHRP output
	ls := script.Script(uhrpScript)
	tx1.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1,
		LockingScript: &ls,
	})

	tx1Bytes := tx1.Bytes()
	tx1ID := tx1.TxID().String()
	t.Logf("UHRP advertisement tx: %s", tx1ID[:16])

	// --- Step 2: Submit to engine ---
	steak, err := engine.Submit(tx1Bytes, []string{UHRPTopicName})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	uhrpResult, ok := steak[UHRPTopicName]
	if !ok {
		t.Fatal("STEAK missing tm_uhrp result")
	}
	if len(uhrpResult.OutputsToAdmit) != 1 || uhrpResult.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected output 0 admitted, got %v", uhrpResult.OutputsToAdmit)
	}
	t.Logf("UHRP output admitted: txid=%s vout=0", tx1ID[:16])

	// --- Step 3: Lookup by content hash ---
	query, _ := json.Marshal(UHRPLookupQuery{ContentHash: contentHash})
	answer, err := engine.Lookup(overlay.LookupQuestion{
		Service: UHRPLookupServiceName,
		Query:   query,
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
	if answer.Outputs[0].Txid != tx1ID {
		t.Fatalf("txid mismatch: got %s, want %s", answer.Outputs[0].Txid, tx1ID)
	}

	// Verify metadata was persisted
	var meta UHRPEntry
	if err := json.Unmarshal(answer.Outputs[0].Metadata, &meta); err != nil {
		t.Fatalf("metadata unmarshal: %v", err)
	}
	if meta.ContentHash != contentHash {
		t.Fatalf("metadata hash mismatch: got %s, want %s", meta.ContentHash, contentHash)
	}
	if meta.URL != "https://anvil.sendbsv.com/content/abc123_0" {
		t.Fatalf("metadata URL mismatch: got %s", meta.URL)
	}
	t.Logf("Lookup found UHRP entry: hash=%s url=%s", meta.ContentHash[:16], meta.URL)

	// --- Step 4: Build a spending transaction (version update) ---
	tx2 := transaction.NewTransaction()
	// This input spends the UHRP output from tx1
	tx1Hash, _ := chainhash.NewHashFromHex(tx1ID)
	tx2.AddInput(&transaction.TransactionInput{
		SourceTXID:       tx1Hash,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	// New UHRP output with updated content hash (v2)
	newContentHash := HashContent([]byte("<html>Hello World v2</html>"))
	newScript, _ := BuildUHRPScript(newContentHash, "https://anvil.sendbsv.com/content/def456_0", "text/html")
	ls2 := script.Script(newScript)
	tx2.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1,
		LockingScript: &ls2,
	})

	tx2Bytes := tx2.Bytes()
	tx2ID := tx2.TxID().String()
	t.Logf("UHRP update tx (spends old): %s", tx2ID[:16])

	// --- Step 5: Submit the spend ---
	steak2, err := engine.Submit(tx2Bytes, []string{UHRPTopicName})
	if err != nil {
		t.Fatalf("Submit spend: %v", err)
	}

	uhrpResult2 := steak2[UHRPTopicName]
	if uhrpResult2 == nil {
		t.Fatal("STEAK missing tm_uhrp result for spend tx")
	}
	if len(uhrpResult2.OutputsToAdmit) != 1 {
		t.Fatalf("expected 1 new output admitted, got %d", len(uhrpResult2.OutputsToAdmit))
	}
	if len(uhrpResult2.CoinsRemoved) != 1 {
		t.Fatalf("expected 1 coin removed, got %d", len(uhrpResult2.CoinsRemoved))
	}
	t.Logf("Old UHRP output removed, new output admitted: txid=%s", tx2ID[:16])

	// --- Step 6: Lookup old hash → not found ---
	query, _ = json.Marshal(UHRPLookupQuery{ContentHash: contentHash})
	answer, err = engine.Lookup(overlay.LookupQuestion{
		Service: UHRPLookupServiceName,
		Query:   query,
	})
	if err != nil {
		t.Fatalf("Lookup old hash: %v", err)
	}
	if len(answer.Outputs) != 0 {
		t.Fatalf("old hash should have 0 results after spend, got %d", len(answer.Outputs))
	}
	t.Logf("Old content hash correctly removed after spend ✓")

	// --- Step 7: Lookup new hash → found ---
	query, _ = json.Marshal(UHRPLookupQuery{ContentHash: newContentHash})
	answer, err = engine.Lookup(overlay.LookupQuestion{
		Service: UHRPLookupServiceName,
		Query:   query,
	})
	if err != nil {
		t.Fatalf("Lookup new hash: %v", err)
	}
	if len(answer.Outputs) != 1 {
		t.Fatalf("expected 1 result for new hash, got %d", len(answer.Outputs))
	}
	if answer.Outputs[0].Txid != tx2ID {
		t.Fatalf("new hash points to wrong txid: got %s, want %s", answer.Outputs[0].Txid, tx2ID)
	}

	var meta2 UHRPEntry
	json.Unmarshal(answer.Outputs[0].Metadata, &meta2)
	t.Logf("New content resolved: hash=%s url=%s ✓", meta2.ContentHash[:16], meta2.URL)
	t.Logf("UHRP end-to-end lifecycle complete: submit → lookup → spend → supersede ✓")
}

// suppress unused imports
var _ = hex.EncodeToString
