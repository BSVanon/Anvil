package routeguard

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/scriptcost"
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

// MalformedScriptCode is ErrMalformedScript's coded 400, following the
// naming style of beefscan.Code and ValidationBudgetCode.
const MalformedScriptCode = "ERR_MALFORMED_SCRIPT"

// ErrMalformedScript marks an unlocking script checkScripts refuses because
// its node-exact parse (scriptcost.EndsMalformed) ends in an undecodable
// instruction. This is a policy refusal, not a consensus rule: under
// Chronicle, go-sdk v1.7.7 lets a signature opcode that executes directly
// inside such an unlocking script re-decode it joined with the spent locking
// script (reparseJoined, script/interpreter/thread.go:1123-1162), so a
// locking script that is one large push becomes one ParsedOpcode per byte --
// a heap bomb with no login and no cost to the sender (cold review round 4,
// B1). The go-sdk comment at thread.go:1129-1134 notes bitcoin-sv decodes the
// same joined bytes, so such a script can be valid under Chronicle when the
// malformed tail follows a top-level OP_RETURN; no honest wallet emits one,
// and before Chronicle the push-only rule already refused it (it sits beside
// SV Node's other non-standard refusals). Refusing unconditionally, for every
// input spv.Verify would run scripts for and regardless of opcode or
// transaction version, is a superset of go-sdk's narrower trigger (a
// signature opcode, Chronicle, and the raw unlocking script specifically):
// DefaultOpcodeParser{nodeExact: true}, the parser the trigger actually uses,
// is unexported, so EndsMalformed is scriptcost's own equivalent decode,
// built from go-sdk's public opcode constants and checked byte for byte
// against go-sdk's own decoder in scriptcost's tests.
var ErrMalformedScript = errors.New("unlocking script ends in an undecodable instruction")

// scanMalformedScripts refuses the first input among g.Unmined whose
// unlocking script's node-exact parse (scriptcost.EndsMalformed) ends in an
// undecodable instruction (see ErrMalformedScript). It runs no script and
// allocates nothing, so PreVerify calls it before taking the execution or
// CPU slot: a flood of this one shape then costs the guard nothing beyond
// parsing the BEEF, instead of queuing behind, or taking, the slots
// legitimate verification work needs (cold review round 4 cycle 6 NIT,
// "slot order" -- this check used to run inside checkScripts, after both
// slots were already taken).
func scanMalformedScripts(g beefnorm.Graph) error {
	for _, tx := range g.Unmined {
		for vin, in := range tx.Inputs {
			if beefnorm.SpentOutput(in) == nil {
				continue // verifyTx fails before any script of tx runs
			}
			if in.UnlockingScript != nil && scriptcost.EndsMalformed(*in.UnlockingScript) {
				return fmt.Errorf("%w: input %d of %s", ErrMalformedScript, vin, tx.TxID())
			}
		}
	}
	return nil
}

// checkScripts runs scriptguard.Check on every input spv.Verify will
// execute, with the flags verifyTx executes it under (spv/verify.go:534-550),
// before any of them runs. scanMalformedScripts must already have cleared g
// by the time this runs (PreVerify calls it first, before any slot is
// taken); this does not repeat that check. It returns an error wrapping
// ErrTooComplex for the first input Check refuses, ctx's error when ctx ends
// first, and otherwise nil, whether or not the scripts would then pass.
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
