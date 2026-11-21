package storage

import (
	"errors"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ancillaryFixture is a stored-data conflict shape. A parent
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
		t.Fatal("go-sdk merged the poisoned BEEF without panicking; this fixture no longer reproduces the conflict")
	}
	if len(target.BUMPs) != 2 {
		t.Fatalf("expected the panicking merge to have added the block-1 proof (2 BUMPs), got %d", len(target.BUMPs))
	}
}

// TestLoadAncillaryBeef_NormalizingAvoidsStoredProofConflict confirms that
// Before a stored ancillary is merged, its BEEF (and the subject's) is
// normalized to beefnorm's canonical proofs, so the subject's short
// (one-level, all-leaves) proof of A and the poisoned ancillary's tall
// (two-level, climbing) proof of A -- the same tree position written two
// different ways -- converge to the identical canonical bytes before
// MergeBeef ever sees them, rather than reaching it as two proofs that
// declare different numbers of levels (TestMergeAncillary_FixtureStillPanicsGoSDK
// pins that an unnormalized merge of this fixture still panics go-sdk v1.7.7).
// So loading both ancillaries now merges everything -- poisoned, F, honest and
// G alongside the subject and A -- rather than skipping poisoned and F. Both
// merge orders, since normalizing both sides makes the merge order-independent.
func TestLoadAncillaryBeef_NormalizingAvoidsStoredProofConflict(t *testing.T) {
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
			t.Fatalf("poisoned first %v: load: %v", poisonedFirst, err)
		}
		for _, id := range []*chainhash.Hash{fx.subject.TxID(), fx.poisoned.TxID(), fx.honest.TxID(), fx.f.TxID(), fx.g.TxID()} {
			if out.Beef.FindTransactionByHash(id) == nil {
				t.Fatalf("poisoned first %v: %s missing from the merged BEEF", poisonedFirst, id)
			}
		}
		if got := len(out.Beef.Transactions); got != 6 {
			t.Fatalf("poisoned first %v: want 6 transactions (subject, A, poisoned, F, honest, G), got %d", poisonedFirst, got)
		}
		levels := map[uint32]int{}
		for _, bump := range out.Beef.BUMPs {
			levels[bump.BlockHeight] = len(bump.Path)
		}
		if len(out.Beef.BUMPs) != 3 || levels[2] != 2 || levels[1] != 1 || levels[3] != 1 {
			t.Fatalf("poisoned first %v: want A's canonical two-level block-2 proof plus F's block-1 and G's block-3 one-level proofs, got %d BUMPs, levels by height %v",
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

// TestLoadAncillaryBeef_TakesOneSnapshotForAnyNumberOfAncillaries confirms
// that merging several successful ancillaries snapshots the
// target itself exactly once, before the first one, not once per ancillary
// (which would also grow with the target, since each successful merge grows
// it, for O(k^2) total cost over k ancillaries). Successful raw blobs are
// retained for a possible rebuild, so there is no ancillary snapshot either:
// snapshotBytes must be called once, for the target before any ancillary.
func TestLoadAncillaryBeef_TakesOneSnapshotForAnyNumberOfAncillaries(t *testing.T) {
	subject := minedTx(0x01, 1)
	subject.MerklePath = soleTxBUMP(subject, 10)
	const n = 5
	ancillaries := make([]*transaction.Transaction, n)
	for i := 0; i < n; i++ {
		seed := byte(0x10 + i)
		tx := minedTx(seed, 1)
		tx.MerklePath = soleTxBUMP(tx, uint32(20+i)) //nolint:gosec // i < n, small
		ancillaries[i] = tx
	}

	s, _ := newStore(t)
	for _, tx := range append([]*transaction.Transaction{subject}, ancillaries...) {
		storeTx(t, s, tx)
	}
	op := &transaction.Outpoint{Txid: *subject.TxID(), Index: 0}
	out, err := s.FindOutput(ctxBg(), op, nil, nil, true)
	if err != nil || out == nil || out.Beef == nil {
		t.Fatalf("find subject: %v", err)
	}
	for _, tx := range ancillaries {
		out.AncillaryTxids = append(out.AncillaryTxids, tx.TxID())
	}

	orig := snapshotBytes
	t.Cleanup(func() { snapshotBytes = orig })
	calls := 0
	snapshotBytes = func(b *transaction.Beef) ([]byte, error) {
		calls++
		return orig(b)
	}

	if err := s.LoadAncillaryBeef(ctxBg(), out); err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, tx := range ancillaries {
		if out.Beef.FindTransactionByHash(tx.TxID()) == nil {
			t.Fatalf("%s missing from the merged BEEF", tx.TxID())
		}
	}
	if calls != 1 {
		t.Fatalf("snapshotBytes called %d times for %d ancillaries, want one target snapshot", calls, n)
	}
}

// TestNewAncillaryMerge_SnapshotPanicIsReported: when the BEEF to merge
// ancillaries into cannot be copied, starting a merge reports it and no
// merge is attempted.
func TestNewAncillaryMerge_SnapshotPanicIsReported(t *testing.T) {
	fx := newAncillaryFixture()
	orig := snapshotBytes
	t.Cleanup(func() { snapshotBytes = orig })
	snapshotBytes = func(*transaction.Beef) ([]byte, error) { panic("serialiser bug") }

	target, err := transaction.NewBeefFromTransaction(fx.subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAncillaryMerge(&target); err == nil || !strings.Contains(err.Error(), "serialisation panicked") {
		t.Fatalf("want the snapshot panic as an error, got %v", err)
	}
}

// TestAncillaryMerge_RebuildFailureIsReported: if the one snapshot taken at
// the start cannot be read back when a merge fails and the target must be
// rebuilt from it, the error says so. target is built directly from the
// subject (bypassing normalizedBeefFromBytes, the same as
// newAncillaryFixture's shape is stored), so merge's own normalization of
// the incoming blob still leaves the two sides' proofs of A at different
// levels and the merge still panics (TestMergeAncillary_FixtureStillPanicsGoSDK
// pins that the fixture does); rebuild's re-parse of the one snapshot
// (safeNewBeefFromBytes, not beefnorm) is the only call through
// newBeefFromBytes this reaches, since merge's own parse of blob goes through
// beefnormParse, not newBeefFromBytes.
func TestAncillaryMerge_RebuildFailureIsReported(t *testing.T) {
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
	m, err := newAncillaryMerge(&target)
	if err != nil {
		t.Fatal(err)
	}
	orig, calls := newBeefFromBytes, 0
	t.Cleanup(func() { newBeefFromBytes = orig })
	newBeefFromBytes = func(b []byte) (*transaction.Beef, error) {
		if calls++; calls == 1 {
			return nil, errors.New("cannot read the snapshot")
		}
		return orig(b)
	}
	err = m.merge(blob)
	if err == nil || !strings.Contains(err.Error(), "merge panicked") || !strings.Contains(err.Error(), "cannot read the snapshot") {
		t.Fatalf("want the merge panic and the rebuild failure in the error, got %v", err)
	}
}
