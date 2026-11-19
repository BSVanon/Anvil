package spv

import (
	"context"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestValidateBEEF_ConsolidationOfAThousandParents: 1,000 parents of one
// block of 2^20 transactions, proven by the one trimmed compound path an
// honest wallet sends, verify in V1 and Atomic form, every ancestor proven;
// Result.BEEF holds the one canonical BUMP, in the format received. A V2
// BEEF is refused as /broadcast has always refused it, for its format.
func TestValidateBEEF_ConsolidationOfAThousandParents(t *testing.T) {
	subject, parents, blk := beefnormtest.Consolidation(1000, 20, 800600)
	v := NewValidator(beefnormtest.Tracker{}.Add(blk))
	bumps := []*transaction.MerklePath{parents[0].MerklePath}
	v2 := beefnormtest.Encode(t, transaction.BEEF_V2, subject, bumps, parents...)
	for name, b := range map[string][]byte{
		"V1":     beefnormtest.Encode(t, transaction.BEEF_V1, subject, bumps, parents...),
		"Atomic": beefnormtest.Atomic(subject, v2),
	} {
		res, err := v.ValidateBEEF(context.Background(), b)
		if err != nil || res.Confidence != ConfidenceSPVVerified || res.TxID != subject.TxID().String() {
			t.Fatalf("%s: %+v, %v", name, res, err)
		}
		if res.Message != "all 1000 merkle proofs verified against local headers" {
			t.Errorf("%s: message %q", name, res.Message)
		}
		tx, err := transaction.NewTransactionFromBEEF(res.BEEF)
		if err != nil || !tx.TxID().IsEqual(subject.TxID()) || tx.Inputs[0].SourceTransaction.MerklePath == nil {
			t.Errorf("%s: Result.BEEF: %v", name, err)
		}
	}
	res, err := v.ValidateBEEF(context.Background(), v2)
	if err != nil || res.Valid || !strings.Contains(res.Message, "a V2 BEEF is accepted only inside an Atomic BEEF") {
		t.Errorf("V2: %+v, %v", res, err)
	}
}

// TestValidateBEEF_CountsProofsByTransaction: two parents mined in one block
// share its one canonical BUMP; both are proven, so the confidence is
// spv_verified, and an unproven grandparent behind a proven parent, which
// verification never reads, is dropped rather than counted.
func TestValidateBEEF_CountsProofsByTransaction(t *testing.T) {
	grandparent := beefnormtest.Parent(20, 1, 2000)
	a := beefnormtest.Spend(grandparent)
	b := beefnormtest.Parent(21, 1, 1000)
	blk := beefnormtest.NewBlock(800601, 4, []*chainhash.Hash{a.TxID(), b.TxID()}, []uint64{3, 9})
	a.MerklePath, b.MerklePath = blk.Proof(0), blk.Proof(1)
	subject := beefnormtest.Spend(a, b)
	beef := beefnormtest.Encode(t, transaction.BEEF_V1, subject, []*transaction.MerklePath{a.MerklePath, b.MerklePath}, grandparent, a, b)
	res, err := NewValidator(beefnormtest.Tracker{}.Add(blk)).ValidateBEEF(context.Background(), beef)
	if err != nil || res.Confidence != ConfidenceSPVVerified {
		t.Fatalf("%+v, %v", res, err)
	}
	kept, err := transaction.NewBeefFromBytes(res.BEEF)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept.BUMPs) != 1 || len(kept.Transactions) != 3 || kept.FindTransactionByHash(grandparent.TxID()) != nil {
		t.Errorf("Result.BEEF: %d BUMPs, %d transactions, want 1 and 3 without the grandparent", len(kept.BUMPs), len(kept.Transactions))
	}
}
