package txrelay

import (
	"log/slog"
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
