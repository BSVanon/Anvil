package beefnorm

import (
	"context"
	"errors"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestGraph_WalksAsVerifyDoes(t *testing.T) {
	p, q := beefnormtest.Parent(20, 1, 1000), beefnormtest.Parent(21, 1, 1000)
	mine(500000, 8, p)
	mine(500001, 8, q)
	m := beefnormtest.Spend(q)
	s := beefnormtest.Spend(p, m)
	n, err := Parse(beefnormtest.Encode(t, transaction.BEEF_V2, s, []*transaction.MerklePath{p.MerklePath, q.MerklePath}, p, q, m))
	if err != nil {
		t.Fatal(err)
	}
	g := n.Graph()
	if len(g.Unmined) != 2 || g.Unmined[0] != n.Tx || !g.Unmined[1].TxID().IsEqual(m.TxID()) {
		t.Errorf("unmined %d, want the subject then m", len(g.Unmined))
	}
	want := map[chainhash.Hash]uint32{*p.TxID(): 500000, *q.TxID(): 500001}
	if len(g.Heights) != len(want) || g.Heights[*p.TxID()] != 500000 || g.Heights[*q.TxID()] != 500001 {
		t.Errorf("heights %v, want %v", g.Heights, want)
	}
}

// efBEEF is a V2 BEEF of p, proven, and s in extended format.
func efBEEF(t *testing.T, p, s *transaction.Transaction) []byte {
	t.Helper()
	ef, err := s.EF()
	if err != nil {
		t.Fatal(err)
	}
	return entries([]*transaction.MerklePath{p.MerklePath}, proven(0, p), append([]byte{0}, ef...))
}

// TestUnbacked: an input whose spent output only the extended format
// supplies is refused, at any depth spv.Verify runs scripts; spv.Verify
// itself accepts it, trusting the output as written. An extended-format
// input whose source transaction the BEEF carries is not refused.
func TestUnbacked(t *testing.T) {
	p := beefnormtest.Parent(22, 1, 1000)
	tracker := beefnormtest.Tracker{}.Add(mine(500002, 8, p))
	fabricated := chainhash.DoubleHashH([]byte("an outpoint no BEEF carries"))

	s := beefnormtest.Spend(p)
	s.AddInput(&transaction.TransactionInput{SourceTXID: &fabricated, UnlockingScript: s.Inputs[0].UnlockingScript, SequenceNumber: transaction.DefaultSequenceNumber})
	s.Inputs[1].SetSourceTxOutput(&transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 5_000_000_000})
	n, err := Parse(efBEEF(t, p, s))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := spv.Verify(context.Background(), n.Tx, tracker, nil); !ok || err != nil {
		t.Fatalf("spv.Verify refuses the fabricated output itself (%v %v); the test shows nothing", ok, err)
	}
	if err := n.Unbacked(); !errors.Is(err, ErrRefused) {
		t.Errorf("subject: %v, want ErrRefused", err)
	}

	backed := beefnormtest.Spend(p)
	n, err = Parse(efBEEF(t, p, backed))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Unbacked(); err != nil {
		t.Errorf("an extended-format input whose source the BEEF carries: %v", err)
	}

	// The same fabricated input one transaction down.
	m := beefnormtest.Spend(p)
	m.AddInput(&transaction.TransactionInput{SourceTXID: &fabricated, UnlockingScript: m.Inputs[0].UnlockingScript, SequenceNumber: transaction.DefaultSequenceNumber})
	m.Inputs[1].SetSourceTxOutput(&transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 5000})
	ef, err := m.EF()
	if err != nil {
		t.Fatal(err)
	}
	top := beefnormtest.Spend(m)
	b := entries([]*transaction.MerklePath{p.MerklePath}, proven(0, p), append([]byte{0}, ef...), raw(top))
	if n, err = Parse(b); err != nil {
		t.Fatal(err)
	}
	if err := n.Unbacked(); !errors.Is(err, ErrRefused) {
		t.Errorf("an ancestor: %v, want ErrRefused", err)
	}
}

func TestSpentOutput(t *testing.T) {
	p := beefnormtest.Parent(23, 2, 1000)
	supplied := &transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 7}
	linked := &transaction.TransactionInput{SourceTXID: p.TxID(), SourceTxOutIndex: 1, SourceTransaction: p}
	if SpentOutput(linked) != p.Outputs[1] {
		t.Error("a linked input does not spend its source's output")
	}
	past := &transaction.TransactionInput{SourceTXID: p.TxID(), SourceTxOutIndex: 2, SourceTransaction: p}
	past.SetSourceTxOutput(supplied)
	if SpentOutput(past) != nil || past.SourceTxOutput() != supplied {
		t.Error("an index past the source's outputs: want nil, as spv.Verify takes it, where SourceTxOutput falls back")
	}
	ef := &transaction.TransactionInput{SourceTXID: p.TxID()}
	ef.SetSourceTxOutput(supplied)
	if SpentOutput(ef) != supplied {
		t.Error("an extended-format input does not spend the supplied output")
	}
}
