package routeguard

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// spendOf is a V2 BEEF of a transaction spending, with unlock, output 0 of a
// parent locked by lock, which is proven alone in a block at height unless
// height is 0, and a tracker that knows that block.
func spendOf(t *testing.T, unlock, lock script.Script, height uint32) ([]byte, beefnormtest.Tracker) {
	t.Helper()
	parent := beefnormtest.Parent(70, 1, 50_000)
	parent.Outputs[0].LockingScript = &lock
	var bumps []*transaction.MerklePath
	tracker := beefnormtest.Tracker{}
	if height > 0 {
		yes := true
		parent.MerklePath = transaction.NewMerklePath(height, [][]*transaction.PathElement{{{Offset: 0, Hash: parent.TxID(), Txid: &yes}}})
		bumps, tracker[height] = []*transaction.MerklePath{parent.MerklePath}, parent.TxID()
	}
	child := transaction.NewTransaction()
	child.AddInputFromTx(parent, 0, nil)
	child.Inputs[0].UnlockingScript = &unlock
	child.AddOutput(&transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 1000})
	return beefnormtest.Encode(t, transaction.BEEF_V2, child, bumps, parent), tracker
}

// multisig is the third review's OP_CHECKMULTISIG shape, spent by
// OP_0 OP_1 OP_1 OP_1: OP_3DUPs grow the signatures to 74,973 and the keys
// to 74,973, all 0x01, so FindAndDelete runs once per signature over the
// whole script code before the engine looks at its context.
var multisig = func() script.Script {
	var lock script.Script
	grow := func(n int) {
		for i := 0; i < n; i++ {
			lock = append(lock, script.Op3DUP)
		}
		_ = lock.AppendPushData(binary.LittleEndian.AppendUint32(nil, uint32(3+3*n))[:3]) //nolint:gosec // n < 2^21
	}
	grow(24990)
	lock = append(lock, script.Op1, script.Op1, script.Op1)
	grow(24990)
	return append(lock, script.OpCHECKMULTISIG)
}()

var multisigUnlock = script.Script{script.Op0, script.Op1, script.Op1, script.Op1}

// TestPreVerify_RefusesAnOpcodeOverItsCost: the multisig shape, whose
// FindAndDelete pre-pass spv.Verify ran for 14.6 s past a 5 s budget, is
// refused with ErrTooComplex before any script runs.
func TestPreVerify_RefusesAnOpcodeOverItsCost(t *testing.T) {
	beef, tracker := spendOf(t, multisigUnlock, multisig, 900_000)
	start := time.Now()
	_, err := verified(t, beef, tracker)
	took := time.Since(start)
	t.Logf("%d bytes refused in %v: %v", len(beef), took, err)
	if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "OP_CHECKMULTISIG") {
		t.Fatalf("PreVerify: %v, want ErrTooComplex naming OP_CHECKMULTISIG", err)
	}
	if took > time.Second {
		t.Errorf("refused after %v", took)
	}
}

// TestCheckScripts_TakesTheFlagsOfTheCoinsHeight: checkScripts prices a
// spend under the flags spv.Verify runs it with, which the spent output's
// height sets. The multisig shape is over the cost cap for an output created
// after Genesis, an unproven one included; for an output created before it,
// the engine's own pre-Genesis limits (10,000-byte scripts, 500 opcodes, 20
// keys: interpreter/config.go:18-23) stop it at once, and checkScripts lets
// it be.
func TestCheckScripts_TakesTheFlagsOfTheCoinsHeight(t *testing.T) {
	for _, c := range []struct {
		name    string
		height  uint32
		refused bool
	}{
		{"created before Genesis", 600_000, false},
		{"created after Genesis", 900_000, true},
		{"unproven", 0, true},
	} {
		beef, _ := spendOf(t, multisigUnlock, multisig, c.height)
		n, err := beefnorm.Parse(beef)
		if err != nil {
			t.Fatal(err)
		}
		err = checkScripts(context.Background(), n.Graph(), nil)
		if refused := errors.Is(err, ErrTooComplex); refused != c.refused || (!refused && err != nil) {
			t.Errorf("%s: %v, want refused %v", c.name, err, c.refused)
		}
	}
}
