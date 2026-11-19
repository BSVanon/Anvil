// Package scriptguard refuses a spend whose scripts could make go-sdk's
// script engine spend longer on one opcode than a verification budget can
// interrupt. The engine (v1.7.7) checks its context between opcodes, and
// inside the few opcodes that loop, but OP_MUL, OP_DIV and OP_MOD on long
// numbers and OP_CHECKMULTISIG's FindAndDelete pre-pass run for seconds
// without looking at it, and OP_RIPEMD160 and OP_NUM2BIN on the largest
// elements for up to about 240 ms.
//
// Check decides before the engine runs, without executing anything: it
// follows the unlocking script and then the locking script the way the
// engine executes them after Genesis, keeping for every stack element only
// an upper bound on its length (and its bytes when short and known, so that
// stack indices, counts and conditions pushed as constants stay exact), and
// following both ways through any conditional it cannot decide. Every bound
// over-approximates, and every path the engine can take is followed, so an
// opcode the engine reaches with operands over a cap is refused; an honest
// script, whose costly operands are hashes and constants, passes.
package scriptguard

import (
	"context"
	"errors"

	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ErrTooCostly is wrapped by Check's refusal: one opcode would cost more
// than one opcode may, or Check cannot show within its own budget that none
// would.
var ErrTooCostly = errors.New("script opcode over its cost cap")

// numLenAfterGenesis is the longest script number for an output created
// after Genesis and before Chronicle: go-sdk's afterGenesisConfig returns
// 750 * 1000 (interpreter/config.go:96-98) and does not export it.
const numLenAfterGenesis = 750_000

// Check reports whether executing input vin of tx, which spends prevout,
// under flags, would run any single opcode whose cost is over the
// per-opcode cap. It returns nil when no opcode is over the cap, whether the
// scripts would then pass or fail (that verdict is spv.Verify's, not
// Check's); an error wrapping ErrTooCostly naming the opcode and the measure
// when one is; and ctx's error when ctx ends first.
//
// Check reads tx and prevout and changes neither, so it may run for several
// transactions at once. It returns nil at once when the scripts hold none
// of the guarded opcodes, or when prevout was created before Genesis, whose
// limits (10,000-byte scripts, 520-byte elements, 4-byte numbers, 20 keys)
// keep every opcode cheap. It assumes the engine run it guards uses go-sdk's
// default stack memory limit (interpreter.DefaultMaxStackMemory), which is
// what keeps every opcode it does not guard under about 130 ms.
func Check(ctx context.Context, tx *transaction.Transaction, vin int, prevout *transaction.TransactionOutput, flags scriptflag.Flag) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !flags.HasFlag(scriptflag.UTXOAfterGenesis) {
		return nil
	}
	if tx == nil || vin < 0 || vin >= len(tx.Inputs) || prevout == nil || prevout.LockingScript == nil {
		return nil // the engine refuses these before executing anything
	}
	a := newAnalyzer(ctx, tx, vin, prevout, flags)
	if !a.progs[0].hasGuarded() && !a.progs[1].hasGuarded() {
		return nil
	}
	return a.run()
}

// newAnalyzer decodes the scripts of input vin of tx, which spends prevout
// after Genesis, for an analysis under flags.
func newAnalyzer(ctx context.Context, tx *transaction.Transaction, vin int, prevout *transaction.TransactionOutput, flags scriptflag.Flag) *analyzer {
	var unlock []byte
	if us := tx.Inputs[vin].UnlockingScript; us != nil {
		unlock = *us
	}
	a := &analyzer{
		ctx:       ctx,
		chronicle: flags.HasFlag(scriptflag.UTXOAfterChronicle),
		forkID:    flags.HasFlag(scriptflag.EnableSighashForkID),
		numLen:    numLenAfterGenesis,
		ver:       []byte{byte(tx.Version), byte(tx.Version >> 8), byte(tx.Version >> 16), byte(tx.Version >> 24)},
		progs:     [2]*prog{decode(unlock), decode(*prevout.LockingScript)},
	}
	if a.chronicle {
		a.numLen = interpreter.MaxScriptNumberLengthAfterChronicle
	}
	return a
}
