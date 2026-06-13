package txrelay

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// buildSpendableChildTx builds a minimal valid child tx (parent + merkle path)
// the local mempool will admit.
func buildSpendableChildTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	parent := transaction.NewTransaction()
	parent.Version = 1
	s, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	parent.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: s})
	txidHash := parent.TxID()
	boolTrue := true
	parent.MerklePath = transaction.NewMerklePath(100, [][]*transaction.PathElement{
		{{Offset: 0, Hash: txidHash, Txid: &boolTrue}, {Offset: 1, Duplicate: &boolTrue}},
	})
	child := transaction.NewTransaction()
	child.Version = 1
	child.AddInput(&transaction.TransactionInput{
		SourceTXID: txidHash, SourceTxOutIndex: 0, SequenceNumber: 0xffffffff, SourceTransaction: parent,
	})
	s2, _ := script.NewFromHex("76a9140000000000000000000000000000000000000000ac")
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 900, LockingScript: s2})
	return child
}

// TestSDKBroadcaster_ARCIsFireAndForget is the core regression for the overlay
// submit-500: the engine calls this synchronously inside Submit, so a slow or
// dead ARC must NOT block the admission response. ARC is best-effort and must
// run fire-and-forget. Here ARC sleeps 3s; BroadcastCtx must still return
// (local-admit success) near-instantly, and ARC must still be invoked async.
func TestSDKBroadcaster_ARCIsFireAndForget(t *testing.T) {
	arcHit := make(chan struct{}, 1)
	slowARC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arcHit <- struct{}{}:
		default:
		}
		time.Sleep(3 * time.Second) // far longer than the admission response should wait
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(ARCResponse{TxID: "abc", Status: "SEEN_ON_NETWORK"})
	}))
	defer slowARC.Close()

	inner := NewBroadcaster(NewMempool(), NewARCClient(slowARC.URL, ""), slog.Default())
	sdk := NewSDKBroadcasterWithLogger(inner, slog.Default())
	tx := buildSpendableChildTx(t)

	start := time.Now()
	success, failure := sdk.BroadcastCtx(context.Background(), tx)
	elapsed := time.Since(start)

	if failure != nil {
		t.Fatalf("local admit must succeed, got failure: %+v", failure)
	}
	if success == nil {
		t.Fatal("expected BroadcastSuccess from local mempool admit")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("BroadcastCtx blocked %v on a slow ARC — ARC must be fire-and-forget", elapsed)
	}

	// ARC must still be fired (just asynchronously).
	select {
	case <-arcHit:
	case <-time.After(2 * time.Second):
		t.Error("ARC was never called — fire-and-forget must still attempt ARC")
	}
}
