package storage

import (
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// --- ConsumedBy / BEEF / blockheight ---------------------------------------

func TestUpdateConsumedBy(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0xAA)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	op := &transaction.Outpoint{Txid: *txid, Index: 0}
	consumers := []*transaction.Outpoint{
		makeOutpoint(0xBB, 0),
		makeOutpoint(0xCC, 1),
	}
	if err := s.UpdateConsumedBy(ctxBg(), op, topicA, consumers); err != nil {
		t.Fatalf("update consumed: %v", err)
	}
	out, err := s.FindOutput(ctxBg(), op, &[]string{topicA}[0], nil, false)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(out.ConsumedBy) != 2 {
		t.Fatalf("expected 2 consumers, got %d", len(out.ConsumedBy))
	}
	if err := s.UpdateConsumedBy(ctxBg(), op, topicA, consumers[:1]); err != nil {
		t.Fatalf("update consumed (shrink): %v", err)
	}
	out, _ = s.FindOutput(ctxBg(), op, &[]string{topicA}[0], nil, false)
	if len(out.ConsumedBy) != 1 {
		t.Fatalf("expected 1 consumer after shrink, got %d", len(out.ConsumedBy))
	}
}

func TestUpdateTransactionBEEF(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0xDD)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	tx := minedTx(0xDD, 1)
	tx.MerklePath = soleTxBUMP(tx, 10)
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("beef of a minimal transaction: %v", err)
	}
	if err := s.UpdateTransactionBEEF(ctxBg(), txid, beef); err != nil {
		t.Fatalf("update beef: %v", err)
	}
	out, err := s.FindOutput(ctxBg(), &transaction.Outpoint{Txid: *txid, Index: 0}, &[]string{topicA}[0], nil, true)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if out.Beef == nil {
		t.Fatal("expected BEEF hydrated")
	}
}

func TestUpdateOutputBlockHeight(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0xEE)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	op := &transaction.Outpoint{Txid: *txid, Index: 0}
	if err := s.UpdateOutputBlockHeight(ctxBg(), op, topicA, 850000, 12); err != nil {
		t.Fatalf("update bh: %v", err)
	}
	out, _ := s.FindOutput(ctxBg(), op, &[]string{topicA}[0], nil, false)
	if out.BlockHeight != 850000 || out.BlockIdx != 12 {
		t.Fatalf("unexpected block info: %+v", out)
	}
	if err := s.UpdateOutputBlockHeight(ctxBg(), op, topicA, 850000, 12); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
}
