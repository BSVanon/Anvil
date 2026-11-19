package storage

import (
	"errors"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ancillaryFixture is cold-review round 3's B3 shape as stored data. A parent
// A is mined in block 2, a block of four transactions. The subject spends
// A:0, and its BEEF proves A with a one-level path that lists all four
// leaves. The poisoned ancillary spends A:1 and F:0, F being the only
// transaction of block 1, and its BEEF proves A with the block's normal
// two-level path; go-sdk lists F's block-1 proof first in that BEEF. Each BEEF
// is valid on its own, but merging the poisoned one into the subject's makes
// go-sdk v1.7.7 panic (merklepath.go:480), after it has already added F's
// block-1 proof. The honest ancillary spends G:0, the only transaction of
// block 3.
type ancillaryFixture struct {
	subject, poisoned, honest *transaction.Transaction
	f, g                      *transaction.Transaction
}

func newAncillaryFixture() ancillaryFixture {
	a := minedTx(0xa0, 2)
	leaves := []*chainhash.Hash{a.TxID()}
	for i := byte(1); i < 4; i++ {
		h := chainhash.DoubleHashH([]byte{i, 0xcc})
		leaves = append(leaves, &h)
	}
	isTxid := true
	short := transaction.NewMerklePath(2, [][]*transaction.PathElement{{
		{Offset: 0, Hash: leaves[0], Txid: &isTxid}, {Offset: 1, Hash: leaves[1]},
		{Offset: 2, Hash: leaves[2]}, {Offset: 3, Hash: leaves[3]},
	}})
	tall := transaction.NewMerklePath(2, [][]*transaction.PathElement{
		{{Offset: 0, Hash: leaves[0], Txid: &isTxid}, {Offset: 1, Hash: leaves[1]}},
		{{Offset: 1, Hash: transaction.MerkleTreeParent(leaves[2], leaves[3])}},
	})
	f, g := minedTx(0xf0, 1), minedTx(0x90, 1)
	f.MerklePath, g.MerklePath = soleTxBUMP(f, 1), soleTxBUMP(g, 3)
	return ancillaryFixture{
		subject:  spendingTx(prevout{withProof(a, short), 0}),
		poisoned: spendingTx(prevout{withProof(a, tall), 1}, prevout{f, 0}),
		honest:   spendingTx(prevout{g, 0}),
		f:        f,
		g:        g,
	}
}

// minedTx returns a transaction with one input from a made-up outpoint and
// the given number of OP_TRUE outputs.
func minedTx(seed byte, outputs int) *transaction.Transaction {
	prev := chainhash.DoubleHashH([]byte{seed, 0xee})
	unlock, lock := script.Script{}, script.Script{script.OpTRUE}
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID: &prev, UnlockingScript: &unlock, SequenceNumber: transaction.DefaultSequenceNumber,
	})
	for i := 0; i < outputs; i++ {
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1000})
	}
	return tx
}

// soleTxBUMP proves tx as the only transaction of the block at height.
func soleTxBUMP(tx *transaction.Transaction, height uint32) *transaction.MerklePath {
	isTxid := true
	return transaction.NewMerklePath(height, [][]*transaction.PathElement{{{Offset: 0, Hash: tx.TxID(), Txid: &isTxid}}})
}

// withProof returns a copy of tx proven by mp, so that two BEEFs can carry
// the same transaction with different proofs.
func withProof(tx *transaction.Transaction, mp *transaction.MerklePath) *transaction.Transaction {
	c := transaction.NewTransaction()
	c.Version, c.Inputs, c.Outputs, c.LockTime = tx.Version, tx.Inputs, tx.Outputs, tx.LockTime
	c.MerklePath = mp
	return c
}

// prevout is an output a test transaction spends.
type prevout struct {
	tx   *transaction.Transaction
	vout uint32
}

// spendingTx returns a transaction with one OP_TRUE output that spends
// prevouts and carries each of their transactions.
func spendingTx(prevouts ...prevout) *transaction.Transaction {
	unlock, lock := script.Script{}, script.Script{script.OpTRUE}
	tx := transaction.NewTransaction()
	for _, p := range prevouts {
		tx.AddInputFromTx(p.tx, p.vout, nil)
		tx.Inputs[len(tx.Inputs)-1].UnlockingScript = &unlock
	}
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 500})
	return tx
}

// storeTx stores tx's output 0 and its BEEF under topic tm_alpha.
func storeTx(t *testing.T, s *Storage, tx *transaction.Transaction) {
	t.Helper()
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("BEEF of %s: %v", tx.TxID(), err)
	}
	if err := s.InsertOutputs(ctxBg(), topicA, tx.TxID(), []uint32{0}, nil, beef, nil); err != nil {
		t.Fatalf("store %s: %v", tx.TxID(), err)
	}
}

// TestMergeAncillary_FixtureStillPanicsGoSDK keeps the fixture honest: an
// unguarded merge of the poisoned BEEF into the subject's still panics, and
// it does so after go-sdk has added F's block-1 proof, which is what the
// restore in mergeStoredBEEF undoes.
func TestMergeAncillary_FixtureStillPanicsGoSDK(t *testing.T) {
	fx := newAncillaryFixture()
	target, err := transaction.NewBeefFromTransaction(fx.subject)
	if err != nil {
		t.Fatal(err)
	}
	poisoned, err := transaction.NewBeefFromTransaction(fx.poisoned)
	if err != nil {
		t.Fatal(err)
	}
	if len(poisoned.BUMPs) != 2 || poisoned.BUMPs[0].BlockHeight != 1 || poisoned.BUMPs[1].BlockHeight != 2 {
		t.Fatalf("the poisoned BEEF must hold the block-1 proof before the block-2 one, got %d BUMPs", len(poisoned.BUMPs))
	}
	panicked := func() (p bool) {
		defer func() { p = recover() != nil }()
		_ = target.MergeBeef(poisoned)
		return false
	}()
	if !panicked {
		t.Fatal("go-sdk merged the poisoned BEEF without panicking; this fixture no longer reproduces cold-review B3")
	}
	if len(target.BUMPs) != 2 {
		t.Fatalf("expected the panicking merge to have added the block-1 proof (2 BUMPs), got %d", len(target.BUMPs))
	}
}

// TestLoadAncillaryBeef_SkipsAncillaryThatCannotMerge: an ancillary BEEF
// whose merge panics is skipped, the BEEF it was merged into is left exactly
// as it was before that merge, every other ancillary still merges, and the
// result serialises for the lookup answer. Both orders: skipping a merge must
// not undo an earlier good one.
func TestLoadAncillaryBeef_SkipsAncillaryThatCannotMerge(t *testing.T) {
	for _, poisonedFirst := range []bool{true, false} {
		fx := newAncillaryFixture()
		s, _ := newStore(t)
		for _, tx := range []*transaction.Transaction{fx.subject, fx.poisoned, fx.honest} {
			storeTx(t, s, tx)
		}
		op := &transaction.Outpoint{Txid: *fx.subject.TxID(), Index: 0}
		out, err := s.FindOutput(ctxBg(), op, nil, nil, true)
		if err != nil || out == nil || out.Beef == nil {
			t.Fatalf("find subject: %v", err)
		}
		out.AncillaryTxids = []*chainhash.Hash{fx.poisoned.TxID(), fx.honest.TxID()}
		if !poisonedFirst {
			out.AncillaryTxids = []*chainhash.Hash{fx.honest.TxID(), fx.poisoned.TxID()}
		}

		if err := s.LoadAncillaryBeef(ctxBg(), out); err != nil {
			t.Fatalf("poisoned first %v: an ancillary that cannot merge failed the load: %v", poisonedFirst, err)
		}
		for _, id := range []*chainhash.Hash{fx.subject.TxID(), fx.honest.TxID(), fx.g.TxID()} {
			if out.Beef.FindTransactionByHash(id) == nil {
				t.Fatalf("poisoned first %v: %s missing from the merged BEEF", poisonedFirst, id)
			}
		}
		for _, id := range []*chainhash.Hash{fx.poisoned.TxID(), fx.f.TxID()} {
			if out.Beef.FindTransactionByHash(id) != nil {
				t.Fatalf("poisoned first %v: %s, from the skipped ancillary, is in the merged BEEF", poisonedFirst, id)
			}
		}
		levels := map[uint32]int{}
		for _, bump := range out.Beef.BUMPs {
			levels[bump.BlockHeight] = len(bump.Path)
		}
		if len(out.Beef.BUMPs) != 2 || levels[2] != 1 || levels[3] != 1 {
			t.Fatalf("poisoned first %v: want the subject's one-level block-2 proof and the honest block-3 proof, got %d BUMPs, levels by height %v",
				poisonedFirst, len(out.Beef.BUMPs), levels)
		}
		atomic, err := out.Beef.AtomicBytes(fx.subject.TxID())
		if err != nil {
			t.Fatalf("poisoned first %v: serialise for the answer: %v", poisonedFirst, err)
		}
		if tx, err := transaction.NewTransactionFromBEEF(atomic); err != nil || !tx.TxID().IsEqual(fx.subject.TxID()) {
			t.Fatalf("poisoned first %v: the answer's BEEF does not carry the subject: %v", poisonedFirst, err)
		}
	}
}

// TestMergeStoredBEEF_SnapshotPanicSkipsTheMerge: when the BEEF to merge into
// cannot be copied, nothing is merged and the target is untouched.
func TestMergeStoredBEEF_SnapshotPanicSkipsTheMerge(t *testing.T) {
	fx := newAncillaryFixture()
	orig := snapshotBytes
	t.Cleanup(func() { snapshotBytes = orig })
	snapshotBytes = func(*transaction.Beef) ([]byte, error) { panic("serialiser bug") }

	target, err := transaction.NewBeefFromTransaction(fx.subject)
	if err != nil {
		t.Fatal(err)
	}
	honest, err := transaction.NewBeefFromTransaction(fx.honest)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := storableBeefBytes(honest)
	if err != nil {
		t.Fatal(err)
	}
	before := target
	err = mergeStoredBEEF(&target, blob)
	if err == nil || !strings.Contains(err.Error(), "serialisation panicked") {
		t.Fatalf("want the snapshot panic as an error, got %v", err)
	}
	if target != before || target.FindTransactionByHash(fx.honest.TxID()) != nil {
		t.Fatal("a merge went ahead without a copy to restore")
	}
}

// TestMergeStoredBEEF_RestoreFailureIsReported: if the copy taken before a
// failed merge cannot be read back, the error says so.
func TestMergeStoredBEEF_RestoreFailureIsReported(t *testing.T) {
	fx := newAncillaryFixture()
	target, err := transaction.NewBeefFromTransaction(fx.subject)
	if err != nil {
		t.Fatal(err)
	}
	poisoned, err := transaction.NewBeefFromTransaction(fx.poisoned)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := storableBeefBytes(poisoned)
	if err != nil {
		t.Fatal(err)
	}
	orig, calls := newBeefFromBytes, 0
	t.Cleanup(func() { newBeefFromBytes = orig })
	newBeefFromBytes = func(b []byte) (*transaction.Beef, error) {
		if calls++; calls == 2 {
			return nil, errors.New("cannot read the copy")
		}
		return orig(b)
	}
	err = mergeStoredBEEF(&target, blob)
	if err == nil || !strings.Contains(err.Error(), "merge panicked") || !strings.Contains(err.Error(), "cannot read the copy") {
		t.Fatalf("want the merge panic and the restore failure in the error, got %v", err)
	}
}
