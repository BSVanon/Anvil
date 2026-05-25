package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	topicA = "tm_alpha"
	topicB = "tm_beta"
)

// --- helpers ----------------------------------------------------------------

func newStore(t *testing.T) (*Storage, *leveldb.DB) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := New(db)
	// Deterministic clock so Score values are predictable in tests.
	s.SetClock(func() time.Time { return time.Unix(1700000000, 0) })
	return s, db
}

func makeHash(seed byte) *chainhash.Hash {
	var h chainhash.Hash
	for i := range h {
		h[i] = seed
	}
	return &h
}

func makeOutpoint(seed byte, idx uint32) *transaction.Outpoint {
	return &transaction.Outpoint{Txid: *makeHash(seed), Index: idx}
}

func ctxBg() context.Context { return context.Background() }

// --- InsertOutputs / FindOutput --------------------------------------------

func TestInsertAndFindOutput(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0x11)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0, 1}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}

	op := &transaction.Outpoint{Txid: *txid, Index: 0}
	top := topicA
	out, err := s.FindOutput(ctxBg(), op, &top, nil, false)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if out.Topic != topicA || out.Outpoint.Index != 0 || out.Spent {
		t.Fatalf("unexpected output: %+v", out)
	}
	if out.MerkleState != engine.MerkleStateUnmined {
		t.Fatalf("expected Unmined, got %v", out.MerkleState)
	}
}

func TestFindOutputAnyTopic(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0x22)
	if err := s.InsertOutputs(ctxBg(), topicB, txid, []uint32{3}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	out, err := s.FindOutput(ctxBg(), &transaction.Outpoint{Txid: *txid, Index: 3}, nil, nil, false)
	if err != nil {
		t.Fatalf("find any-topic: %v", err)
	}
	if out.Topic != topicB {
		t.Fatalf("expected topic %s, got %s", topicB, out.Topic)
	}
}

func TestFindOutputSpentFilter(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0x33)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	op := &transaction.Outpoint{Txid: *txid, Index: 0}
	top := topicA
	spentTrue := true
	if _, err := s.FindOutput(ctxBg(), op, &top, &spentTrue, false); err != engine.ErrNotFound {
		t.Fatalf("expected ErrNotFound for spent=true on unspent, got %v", err)
	}
	spentFalse := false
	if _, err := s.FindOutput(ctxBg(), op, &top, &spentFalse, false); err != nil {
		t.Fatalf("expected success for spent=false, got %v", err)
	}
}

func TestFindOutputsBatch_PositionalNilPadded(t *testing.T) {
	// Positional contract: len(out) == len(outpoints), out[i] == nil where
	// no record matched (or outpoints[i] was nil). This is what the
	// upstream engine.mergeExistingOutputs depends on — it iterates with
	// `for vin, output := range outputs` and treats the slice index as the
	// real input vin, skipping nil entries. Compacting misses out would
	// silently renumber sparse spends. (Codex review 16624e3045f4f808.)
	s, _ := newStore(t)
	txid := makeHash(0x44)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0, 1, 2}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	ops := []*transaction.Outpoint{
		{Txid: *txid, Index: 0}, // present
		{Txid: *txid, Index: 5}, // missing
		nil,                     // nil entry
		{Txid: *txid, Index: 2}, // present
	}
	out, err := s.FindOutputs(ctxBg(), ops, topicA, nil, false)
	if err != nil {
		t.Fatalf("find outputs: %v", err)
	}
	if len(out) != len(ops) {
		t.Fatalf("positional contract violated: got len=%d want len=%d", len(out), len(ops))
	}
	if out[0] == nil || out[0].Outpoint.Index != 0 {
		t.Fatalf("out[0] should be present record with index 0, got %+v", out[0])
	}
	if out[1] != nil {
		t.Fatalf("out[1] should be nil (missing record), got %+v", out[1])
	}
	if out[2] != nil {
		t.Fatalf("out[2] should be nil (nil outpoint), got %+v", out[2])
	}
	if out[3] == nil || out[3].Outpoint.Index != 2 {
		t.Fatalf("out[3] should be present record with index 2, got %+v", out[3])
	}
}

// TestFindOutputsBatch_SparseSpendsKeepInputIndices simulates the call
// shape that engine.mergeExistingOutputs would make: it asks for the
// previously-admitted UTXOs spent by the inputs of a hypothetical tx where
// only vins 0 and 3 spend topic-known outputs (vins 1, 2 are unrelated).
// The returned slice must keep nil at indices 1 and 2 so the engine
// correctly computes previousCoins = [0, 3] rather than [0, 1].
func TestFindOutputsBatch_SparseSpendsKeepInputIndices(t *testing.T) {
	s, _ := newStore(t)
	hostTxid := makeHash(0x60)
	if err := s.InsertOutputs(ctxBg(), topicA, hostTxid, []uint32{0, 1}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// inpoints[0] and inpoints[3] reference known outputs; 1 and 2 don't.
	inpoints := []*transaction.Outpoint{
		{Txid: *hostTxid, Index: 0},
		{Txid: *makeHash(0x99), Index: 0}, // not in storage
		{Txid: *makeHash(0x99), Index: 1}, // not in storage
		{Txid: *hostTxid, Index: 1},
	}
	out, err := s.FindOutputs(ctxBg(), inpoints, topicA, nil, false)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("expected len 4, got %d", len(out))
	}
	// Recompute previousCoins exactly as engine.mergeExistingOutputs does.
	var previousCoins []uint32
	for vin, output := range out {
		if output == nil {
			continue
		}
		previousCoins = append(previousCoins, uint32(vin))
	}
	if len(previousCoins) != 2 || previousCoins[0] != 0 || previousCoins[1] != 3 {
		t.Fatalf("previousCoins reconstruction failed: got %v, expected [0 3]", previousCoins)
	}
}

func TestFindOutputsForTransaction(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0x55)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0, 1}, nil, nil, nil); err != nil {
		t.Fatalf("insert A: %v", err)
	}
	if err := s.InsertOutputs(ctxBg(), topicB, txid, []uint32{0}, nil, nil, nil); err != nil {
		t.Fatalf("insert B: %v", err)
	}
	out, err := s.FindOutputsForTransaction(ctxBg(), txid, false)
	if err != nil {
		t.Fatalf("find for tx: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 results across topics, got %d", len(out))
	}
}

func TestFindUTXOsForTopic_SinceAndLimit(t *testing.T) {
	s, db := newStore(t)
	// Three outputs in topicA, all admitted at score=1700000000.
	txid := makeHash(0x66)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0, 1, 2}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// since=0 returns everything; limit caps result.
	out, err := s.FindUTXOsForTopic(ctxBg(), topicA, 0, 2, false)
	if err != nil {
		t.Fatalf("find utxos: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 (limit), got %d", len(out))
	}
	// since=score+1 (future) returns nothing.
	out, err = s.FindUTXOsForTopic(ctxBg(), topicA, 1700000001, 0, false)
	if err != nil {
		t.Fatalf("find utxos future: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 results, got %d", len(out))
	}
	_ = db
}

func TestMarkUTXOsAsSpent_DropsFromUtxoScan(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0x77)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0, 1}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	spent := makeHash(0x99)
	if err := s.MarkUTXOsAsSpent(ctxBg(), []*transaction.Outpoint{{Txid: *txid, Index: 0}}, topicA, spent); err != nil {
		t.Fatalf("mark spent: %v", err)
	}
	// Spent output should still be findable via FindOutput.
	out, err := s.FindOutput(ctxBg(), &transaction.Outpoint{Txid: *txid, Index: 0}, &[]string{topicA}[0], nil, false)
	if err != nil {
		t.Fatalf("find spent: %v", err)
	}
	if !out.Spent {
		t.Fatalf("expected spent=true")
	}
	// But should NOT appear in FindUTXOsForTopic.
	all, err := s.FindUTXOsForTopic(ctxBg(), topicA, 0, 0, false)
	if err != nil {
		t.Fatalf("find utxos: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 remaining UTXO, got %d", len(all))
	}
}

func TestDeleteOutput(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0x88)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	op := &transaction.Outpoint{Txid: *txid, Index: 0}
	if err := s.DeleteOutput(ctxBg(), op, topicA); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.FindOutput(ctxBg(), op, &[]string{topicA}[0], nil, false); err != engine.ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	// Idempotent re-delete.
	if err := s.DeleteOutput(ctxBg(), op, topicA); err != nil {
		t.Fatalf("re-delete: %v", err)
	}
}

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
	// Replace with a smaller set.
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
	beef := transaction.NewBeef()
	if err := s.UpdateTransactionBEEF(ctxBg(), txid, beef); err != nil {
		t.Fatalf("update beef: %v", err)
	}
	out, err := s.FindOutput(ctxBg(), &transaction.Outpoint{Txid: *txid, Index: 0}, &[]string{topicA}[0], nil, true)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if out.Beef == nil {
		t.Fatalf("expected BEEF hydrated")
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
	// Idempotent.
	if err := s.UpdateOutputBlockHeight(ctxBg(), op, topicA, 850000, 12); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
}

// --- Applied dedup ----------------------------------------------------------

func TestAppliedTransactionDedup(t *testing.T) {
	s, _ := newStore(t)
	tx := &overlay.AppliedTransaction{Topic: topicA, Txid: makeHash(0xF0)}
	exists, err := s.DoesAppliedTransactionExist(ctxBg(), tx)
	if err != nil || exists {
		t.Fatalf("expected absent, got %v exists=%v", err, exists)
	}
	if err := s.InsertAppliedTransaction(ctxBg(), tx); err != nil {
		t.Fatalf("insert applied: %v", err)
	}
	exists, err = s.DoesAppliedTransactionExist(ctxBg(), tx)
	if err != nil || !exists {
		t.Fatalf("expected present, got %v exists=%v", err, exists)
	}
}

// --- Peer interaction -------------------------------------------------------

func TestPeerInteractionRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	got, err := s.GetLastInteraction(ctxBg(), "peer.example", topicA)
	if err != nil || got != 0 {
		t.Fatalf("expected default 0, got %v err=%v", got, err)
	}
	if err := s.UpdateLastInteraction(ctxBg(), "peer.example", topicA, 1234567890.5); err != nil {
		t.Fatalf("update peer: %v", err)
	}
	got, err = s.GetLastInteraction(ctxBg(), "peer.example", topicA)
	if err != nil {
		t.Fatalf("get peer: %v", err)
	}
	if got != 1234567890.5 {
		t.Fatalf("expected 1234567890.5, got %v", got)
	}
}

// --- Merkle state -----------------------------------------------------------

func TestFindOutpointsByMerkleState(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0xA0)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0, 1, 2}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	ops, err := s.FindOutpointsByMerkleState(ctxBg(), topicA, engine.MerkleStateUnmined, 0)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("expected 3 Unmined, got %d", len(ops))
	}
	// Other states empty.
	ops, _ = s.FindOutpointsByMerkleState(ctxBg(), topicA, engine.MerkleStateValidated, 0)
	if len(ops) != 0 {
		t.Fatalf("expected 0 Validated, got %d", len(ops))
	}
}

func TestReconcileMerkleRoot_StateTransitions(t *testing.T) {
	s, _ := newStore(t)
	txid := makeHash(0xB0)
	if err := s.InsertOutputs(ctxBg(), topicA, txid, []uint32{0, 1}, nil, nil, nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Without a merkle root or block height set, reconcile is a no-op:
	// nothing matches blockHeight==argument.
	if err := s.ReconcileMerkleRoot(ctxBg(), topicA, 100, makeHash(0xC0)); err != nil {
		t.Fatalf("reconcile no-op: %v", err)
	}
	op0 := &transaction.Outpoint{Txid: *txid, Index: 0}
	if err := s.UpdateOutputBlockHeight(ctxBg(), op0, topicA, 100, 5); err != nil {
		t.Fatalf("bh: %v", err)
	}
	// Manually stamp a merkle root so we can verify the match path. (In
	// W-5 wiring this will come from BEEF extraction; phase A doesn't
	// own that path.)
	rec, _ := s.loadRecord(op0, &[]string{topicA}[0])
	rec.MerkleRoot = makeHash(0xC0)
	body, _ := encodeRecord(rec)
	_ = s.db.Put(outputKey(topicA, op0), body, nil)

	if err := s.ReconcileMerkleRoot(ctxBg(), topicA, 100, makeHash(0xC0)); err != nil {
		t.Fatalf("reconcile match: %v", err)
	}
	out, _ := s.FindOutput(ctxBg(), op0, &[]string{topicA}[0], nil, false)
	if out.MerkleState != engine.MerkleStateValidated {
		t.Fatalf("expected Validated, got %v", out.MerkleState)
	}
	// Index migrated to the Validated bucket.
	valid, _ := s.FindOutpointsByMerkleState(ctxBg(), topicA, engine.MerkleStateValidated, 0)
	if len(valid) != 1 {
		t.Fatalf("expected 1 Validated, got %d", len(valid))
	}
}

// --- LoadAncillaryBeef ------------------------------------------------------

func TestLoadAncillaryBeef_MissingBeef(t *testing.T) {
	s, _ := newStore(t)
	out := &engine.Output{
		Outpoint: transaction.Outpoint{Txid: *makeHash(0xF1), Index: 0},
	}
	if err := s.LoadAncillaryBeef(ctxBg(), out); err != engine.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
