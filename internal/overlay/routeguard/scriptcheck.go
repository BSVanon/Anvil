package routeguard

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/scriptguard"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// unminedHeight is the height spv.Verify gives a transaction that is in no
// block (spv/script_flags.go:11-13).
const unminedHeight uint32 = math.MaxUint32

// checkScripts runs scriptguard.Check on every input spv.Verify will
// execute, with the flags verifyTx executes it under (spv/verify.go:534-550),
// before any of them runs. It returns an error wrapping ErrTooComplex for the
// first input Check refuses, ctx's error when ctx ends first, and otherwise
// nil, whether or not the scripts would then pass.
func checkScripts(ctx context.Context, g beefnorm.Graph, tracker chaintracker.ChainTracker) error {
	heights := scriptflag.MainNetActivationHeights
	if p, ok := tracker.(spv.ActivationHeightsProvider); ok {
		heights = p.ActivationHeights()
	}
	for _, tx := range g.Unmined {
		for vin, in := range tx.Inputs {
			prevout := beefnorm.SpentOutput(in)
			if prevout == nil {
				continue // verifyTx fails before any script of tx runs
			}
			flags := heights.BlockValidationFlags(coinHeight(g, in, prevout, heights), unminedHeight)
			err := scriptguard.Check(ctx, tx, vin, prevout, flags)
			if errors.Is(err, scriptguard.ErrTooCostly) {
				return fmt.Errorf("%w: input %d of %s: %w", ErrTooComplex, vin, tx.TxID(), err)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// coinHeight is the height spv.Verify takes the output in spends to have
// been created at: its source transaction's proven height, or unminedHeight,
// except that a P2SH-shaped output that no proven coinbase created is taken
// as created before Genesis (p2shCoinHeight, spv/verify.go:563-593).
func coinHeight(g beefnorm.Graph, in *transaction.TransactionInput, prevout *transaction.TransactionOutput, heights scriptflag.ActivationHeights) uint32 {
	height, proven := g.Heights[*in.SourceTXID]
	if !proven {
		height = unminedHeight
	}
	if heights.Genesis == 0 || prevout.LockingScript == nil || !prevout.LockingScript.IsP2SH() {
		return height
	}
	if src := in.SourceTransaction; src != nil && proven && isCoinbase(src) {
		return height
	}
	return min(height, heights.Genesis-1)
}

// isCoinbase is spv's node-exact test (spv/verify.go:732-743): exactly one
// input, spending the null outpoint.
func isCoinbase(tx *transaction.Transaction) bool {
	if len(tx.Inputs) != 1 || tx.Inputs[0].SourceTXID == nil {
		return false
	}
	return *tx.Inputs[0].SourceTXID == (chainhash.Hash{}) && tx.Inputs[0].SourceTxOutIndex == transaction.DefaultSequenceNumber
}
