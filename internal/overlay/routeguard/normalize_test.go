package routeguard

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// verified reads beef through ReadBody on a new ticket of a roomy guard and
// runs PreVerify on it with tracker.
func verified(t *testing.T, beef []byte, tracker chaintracker.ChainTracker) (*Submit, error) {
	t.Helper()
	g := New(1<<32, 4, 4, testWait)
	tk, err := g.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/submit", bytes.NewReader(beef))
	if _, err := tk.ReadBody(httptest.NewRecorder(), r, BEEFRoute); err != nil {
		t.Fatal(err)
	}
	sub, err := tk.PreVerify(context.Background(), tracker, func(string) bool { return true }, beef, []string{"tm_test"})
	if err != nil {
		tk.Close()
		return nil, err
	}
	t.Cleanup(sub.Done)
	return sub, nil
}

// efBEEF is a V2 BEEF of one transaction in extended format whose only input
// spends an output, locked by lock, of a transaction the BEEF does not hold:
// the extended format alone supplies it.
func efBEEF(t *testing.T, lock script.Script) []byte {
	t.Helper()
	prev := chainhash.DoubleHashH([]byte("an output no BEEF holds"))
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &prev, UnlockingScript: &script.Script{}, SequenceNumber: transaction.DefaultSequenceNumber})
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 10_000, LockingScript: &lock})
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 1000})
	ef, err := tx.EF()
	if err != nil {
		t.Fatal(err)
	}
	b := binary.LittleEndian.AppendUint32(nil, transaction.BEEF_V2)
	b = append(b, 0, 1, 0) // no BUMPs, one raw transaction
	return append(b, ef...)
}

// TestPreVerify_ConsolidationOfAThousandParents: a transaction spending 1,000
// parents mined in one block of 2^20 transactions, proven by the one trimmed
// compound path an honest wallet sends, passes in V1, V2 and Atomic form;
// the engine gets one canonical BUMP and an Atomic BEEF go-sdk reads.
func TestPreVerify_ConsolidationOfAThousandParents(t *testing.T) {
	subject, parents, blk := beefnormtest.Consolidation(1000, 20, 800500)
	tracker := beefnormtest.Tracker{}.Add(blk)
	bumps := []*transaction.MerklePath{parents[0].MerklePath}
	v2 := beefnormtest.Encode(t, transaction.BEEF_V2, subject, bumps, parents...)
	for name, b := range map[string][]byte{
		"V1":     beefnormtest.Encode(t, transaction.BEEF_V1, subject, bumps, parents...),
		"V2":     v2,
		"Atomic": beefnormtest.Atomic(subject, v2),
	} {
		sub, err := verified(t, b, tracker)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(sub.Beef.BUMPs) != 1 || len(sub.Beef.Transactions) != 1001 {
			t.Errorf("%s: %d BUMPs and %d transactions, want 1 and 1001", name, len(sub.Beef.BUMPs), len(sub.Beef.Transactions))
		}
		if _, txid, err := transaction.NewBeefFromAtomicBytes(sub.Atomic); err != nil || !txid.IsEqual(subject.TxID()) {
			t.Errorf("%s: the Atomic BEEF for the engine: %v, subject %v", name, err, txid)
		}
	}
}

// TestPreVerify_HandsTheEngineOnlyTheSubjectsGraph: an Atomic BEEF holding a
// transaction outside its subject's graph, as ts-sdk 2.1.0's
// Beef.getBeefForAtomic leaves an older unrelated one, which go-sdk's own
// Atomic parser refuses, passes; neither the BEEF the engine stores nor the
// Atomic BEEF its lookup services read holds the unrelated transaction.
func TestPreVerify_HandsTheEngineOnlyTheSubjectsGraph(t *testing.T) {
	yes := true
	parent := beefnormtest.Parent(9, 1, 1000)
	parent.MerklePath = transaction.NewMerklePath(800501, [][]*transaction.PathElement{{{Offset: 0, Hash: parent.TxID(), Txid: &yes}}})
	unrelated := beefnormtest.Parent(10, 1, 1000)
	subject := beefnormtest.Spend(parent)
	b := beefnormtest.Atomic(subject, beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{parent.MerklePath}, unrelated, parent))
	if _, _, err := transaction.NewBeefFromAtomicBytes(b); err == nil {
		t.Fatal("go-sdk accepts the unrelated transaction; the case is not the one ts-sdk sends")
	}
	sub, err := verified(t, b, beefnormtest.Tracker{800501: parent.TxID()})
	if err != nil {
		t.Fatal(err)
	}
	if sub.Beef.FindTransactionByHash(unrelated.TxID()) != nil {
		t.Error("the BEEF for the engine holds the unrelated transaction")
	}
	atomic, _, err := transaction.NewBeefFromAtomicBytes(sub.Atomic)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.FindTransactionByHash(unrelated.TxID()) != nil || atomic.FindTransactionByHash(parent.TxID()) == nil {
		t.Error("the Atomic BEEF for the lookup services holds the unrelated transaction or lacks the parent")
	}
}

// TestPreVerify_RefusesSpendsOnlyTheExtendedFormatBacks: a transaction whose
// spent output only the extended format supplies is refused before its
// scripts are priced or run, however few they are.
func TestPreVerify_RefusesSpendsOnlyTheExtendedFormatBacks(t *testing.T) {
	_, err := verified(t, efBEEF(t, script.Script{script.OpTRUE}), beefnormtest.Tracker{})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// TestScriptWeight_PricesTheOutputSpvVerifyRuns: an input is priced with the
// output spv.Verify runs it against, the one the extended format supplies
// included, so 200,002 instructions there are over MaxScriptOps and an
// OP_CAT there takes the execution slot.
func TestScriptWeight_PricesTheOutputSpvVerifyRuns(t *testing.T) {
	long := append(bytes.Repeat([]byte{script.OpNOP}, 200_000), script.OpCAT, script.OpTRUE)
	for _, c := range []struct {
		name   string
		lock   script.Script
		over   bool
		copies bool
	}{
		{"over the cap", long, true, false},
		{"writes", script.Script{script.Op1, script.OpDUP, script.OpCAT}, false, true},
	} {
		n, err := beefnorm.Parse(efBEEF(t, c.lock))
		if err != nil {
			t.Fatal(err)
		}
		_, copies, err := scriptWeight(n.Tx, n.Graph().Unmined)
		if errors.Is(err, ErrTooComplex) != c.over || (!c.over && copies != c.copies) {
			t.Errorf("%s: copies %v, err %v", c.name, copies, err)
		}
	}
}

// TestCoinHeight: the height an output's scripts run under is its source's
// proven height or, unproven, an unmined one, except that a P2SH-shaped
// output no proven coinbase created counts as created before Genesis, as
// spv.Verify's p2shCoinHeight takes it.
func TestCoinHeight(t *testing.T) {
	heights := scriptflag.MainNetActivationHeights
	p2sh := script.Script(append(append([]byte{script.OpHASH160, 20}, make([]byte, 20)...), script.OpEQUAL))
	if !p2sh.IsP2SH() {
		t.Fatal("not P2SH")
	}
	src := beefnormtest.Parent(11, 1, 1000)
	coinbase := transaction.NewTransaction()
	coinbase.AddInput(&transaction.TransactionInput{SourceTXID: &chainhash.Hash{}, SourceTxOutIndex: transaction.DefaultSequenceNumber, UnlockingScript: &script.Script{}})
	coinbase.AddOutput(&transaction.TransactionOutput{LockingScript: &p2sh, Satoshis: 1})
	for _, c := range []struct {
		name   string
		src    *transaction.Transaction
		lock   script.Script
		proven bool
		want   uint32
	}{
		{"proven", src, script.Script{script.OpTRUE}, true, 900000},
		{"unproven", src, script.Script{script.OpTRUE}, false, unminedHeight},
		{"P2SH, unproven", src, p2sh, false, heights.Genesis - 1},
		{"P2SH, proven after Genesis", src, p2sh, true, heights.Genesis - 1},
		{"P2SH of a proven coinbase", coinbase, p2sh, true, 900000},
		{"P2SH of an unproven coinbase", coinbase, p2sh, false, heights.Genesis - 1},
	} {
		in := &transaction.TransactionInput{SourceTXID: c.src.TxID(), SourceTransaction: c.src}
		g := beefnorm.Graph{Heights: map[chainhash.Hash]uint32{}}
		if c.proven {
			g.Heights[*c.src.TxID()] = 900000
		}
		if got := coinHeight(g, in, &transaction.TransactionOutput{LockingScript: &c.lock}, heights); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
