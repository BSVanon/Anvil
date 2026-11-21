package api

import (
	"bytes"
	"context"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func brc121DependencyChain() (*transaction.Transaction, *transaction.Transaction) {
	lock := script.Script{0x51}
	source := transaction.NewTransaction()
	source.AddOutput(&transaction.TransactionOutput{Satoshis: 1000, LockingScript: &lock})
	source.MerklePath = transaction.NewMerklePath(1, nil)
	parent := transaction.NewTransaction()
	parent.AddInput(&transaction.TransactionInput{SourceTXID: source.TxID(), SourceTxOutIndex: 0, SourceTransaction: source})
	parent.AddOutput(&transaction.TransactionOutput{Satoshis: 900, LockingScript: &lock})
	child := transaction.NewTransaction()
	child.AddInput(&transaction.TransactionInput{SourceTXID: parent.TxID(), SourceTxOutIndex: 0, SourceTransaction: parent})
	child.AddOutput(&transaction.TransactionOutput{Satoshis: 800, LockingScript: &lock})
	return parent, child
}

func TestBRC121UnconfirmedAncestorsSubmittedInDependencyOrder(t *testing.T) {
	arc, _ := newBRC121Stub()
	parent, child := brc121DependencyChain()
	if _, err := submitBRC121With(context.Background(), &brc121Payment{tx: child}, false, arc.send); err != nil {
		t.Fatal(err)
	}
	parentEF, _ := parent.EF()
	childEF, _ := child.EF()
	arc.mu.Lock()
	defer arc.mu.Unlock()
	if len(arc.bodies) != 2 || !bytes.Equal(arc.bodies[0], parentEF) || !bytes.Equal(arc.bodies[1], childEF) {
		t.Fatalf("ARC bodies were not parent then payment: %d submits", len(arc.bodies))
	}
}

func TestBRC121ProvenPaymentIsStillSubmitted(t *testing.T) {
	_, child := brc121DependencyChain()
	child.MerklePath = transaction.NewMerklePath(2, nil)
	order := brc121SubmitOrder(child)
	if len(order) != 1 || order[0] != child {
		t.Fatalf("proven payment submit order is %+v", order)
	}
}

func TestBRC121SweepHasReservedSubmitSlot(t *testing.T) {
	for i := 0; i < maxDirectPaymentSubmits; i++ {
		directPaymentSubmitSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxDirectPaymentSubmits; i++ {
			<-directPaymentSubmitSlots
		}
	}()
	arc, _ := newBRC121Stub()
	_, child := brc121DependencyChain()
	if _, err := submitBRC121With(context.Background(), &brc121Payment{tx: child}, true, arc.send); err != nil {
		t.Fatalf("reserved sweep submit failed: %v", err)
	}
	if arc.calls.Load() != 2 {
		t.Fatalf("sweep submitted %d transactions, want ancestor and payment", arc.calls.Load())
	}
}
