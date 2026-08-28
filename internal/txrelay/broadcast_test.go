package txrelay

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func testBroadcaster() *Broadcaster {
	return NewBroadcaster(NewMempool(), nil, slog.Default())
}

func buildTestBEEF(t *testing.T) []byte {
	t.Helper()

	parent := transaction.NewTransaction()
	parent.Version = 1
	s, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	parent.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: s,
	})

	txidHash := parent.TxID()
	boolTrue := true
	parent.MerklePath = transaction.NewMerklePath(100, [][]*transaction.PathElement{
		{
			{Offset: 0, Hash: txidHash, Txid: &boolTrue},
			{Offset: 1, Duplicate: &boolTrue},
		},
	})

	child := transaction.NewTransaction()
	child.Version = 1
	child.AddInput(&transaction.TransactionInput{
		SourceTXID:        txidHash,
		SourceTxOutIndex:  0,
		SequenceNumber:    0xffffffff,
		SourceTransaction: parent,
	})
	s2, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	child.AddOutput(&transaction.TransactionOutput{
		Satoshis:      900,
		LockingScript: s2,
	})

	beefBytes, err := child.BEEF()
	if err != nil {
		t.Fatalf("encode BEEF: %v", err)
	}
	return beefBytes
}

// buildChildWithParent returns a tx whose single input carries its
// SourceTransaction — so tx.EF() can annotate the input and produce extended
// format.
func buildChildWithParent(t *testing.T) *transaction.Transaction {
	t.Helper()
	s, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	parent := transaction.NewTransaction()
	parent.Version = 1
	parent.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: s})

	child := transaction.NewTransaction()
	child.Version = 1
	child.AddInput(&transaction.TransactionInput{
		SourceTXID:        parent.TxID(),
		SourceTxOutIndex:  0,
		SequenceNumber:    0xffffffff,
		SourceTransaction: parent,
		UnlockingScript:   s,
	})
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 900, LockingScript: s})
	return child
}

// buildBareInputTx returns a tx with an input but NO SourceTransaction — tx.EF()
// cannot annotate it, so BroadcastToARCTx must fall back to raw bytes.
func buildBareInputTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	s, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	seed := transaction.NewTransaction()
	seed.Version = 1
	seed.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: s})

	tx := transaction.NewTransaction()
	tx.Version = 1
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       seed.TxID(),
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
		UnlockingScript:  s,
		// SourceTransaction deliberately nil
	})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 900, LockingScript: s})
	return tx
}

// TestBroadcastToARCTxWireFormat pins the EF-vs-raw contract of the HTTP
// /broadcast path (distinct from the SDK-adapter EF path): a tx that carries its
// input ancestry goes to ARC as extended format (0x0000000000EF marker after the
// 4-byte version); a tx that lacks ancestry falls back to raw bytes.
func TestBroadcastToARCTxWireFormat(t *testing.T) {
	var received []byte
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"txid": "00", "txStatus": "SEEN_ON_NETWORK"})
	}))
	defer mock.Close()

	b := NewBroadcaster(NewMempool(), NewARCClient(mock.URL, ""), slog.Default())
	efMarker := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xEF}

	// With ancestry -> extended format.
	child := buildChildWithParent(t)
	if _, err := b.BroadcastToARCTx(child); err != nil {
		t.Fatalf("BroadcastToARCTx(child): %v", err)
	}
	if len(received) < 10 || !bytes.Equal(received[4:10], efMarker) {
		t.Errorf("tx with ancestry: want EF marker at bytes[4:10], got % x", received[:min(12, len(received))])
	}

	// Without ancestry -> raw (no EF marker), byte-identical to tx.Bytes().
	bare := buildBareInputTx(t)
	if _, err := b.BroadcastToARCTx(bare); err != nil {
		t.Fatalf("BroadcastToARCTx(bare): %v", err)
	}
	if len(received) >= 10 && bytes.Equal(received[4:10], efMarker) {
		t.Errorf("bare tx: expected raw wire, got EF marker")
	}
	if !bytes.Equal(received, bare.Bytes()) {
		t.Errorf("bare tx: ARC wire must equal raw tx bytes")
	}
}

func TestBroadcastBEEF(t *testing.T) {
	b := testBroadcaster()
	beef := buildTestBEEF(t)

	result, err := b.BroadcastBEEF(beef)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted {
		t.Fatal("expected accepted")
	}
	if result.TxID == "" {
		t.Fatal("expected non-empty txid")
	}

	// Should be in mempool
	if !b.Mempool().Has(result.TxID) {
		t.Fatal("expected tx in mempool after broadcast")
	}
}

func TestBroadcastBEEFIdempotent(t *testing.T) {
	b := testBroadcaster()
	beef := buildTestBEEF(t)

	r1, _ := b.BroadcastBEEF(beef)
	r2, _ := b.BroadcastBEEF(beef)

	if r1.TxID != r2.TxID {
		t.Fatal("same BEEF should produce same txid")
	}
	// Mempool should still have exactly 1
	if b.Mempool().Count() != 1 {
		t.Fatalf("expected 1 tx in mempool, got %d", b.Mempool().Count())
	}
}

func TestBroadcastToARCWithoutConfig(t *testing.T) {
	b := testBroadcaster() // no ARC configured
	_, err := b.BroadcastToARC([]byte{0x01})
	if err == nil {
		t.Fatal("expected error when ARC not configured")
	}
}

func TestBroadcastRawInvalidTx(t *testing.T) {
	b := testBroadcaster()
	_, err := b.BroadcastRaw([]byte("not a transaction"))
	if err == nil {
		t.Fatal("expected error for invalid raw tx")
	}
}
