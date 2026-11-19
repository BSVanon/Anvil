package routeguard

import (
	"fmt"

	"github.com/BSVanon/Anvil/internal/scriptcost"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// What a submit's scripts can cost, from go-sdk v1.7.7 measured on amd64.
//
// spv.Verify runs every input of every unproven transaction in the BEEF, and
// its interpreter first parses the unlocking script and the locking script it
// spends into one value per instruction, everything after an OP_RETURN
// included: 5.8 million one-byte instructions held 712 MiB, and 2.9 million
// OP_1 with as many OP_DROP 861 MiB, some 128 to 156 bytes an instruction
// live. The engine verifies once more after the guard's own verification:
// through /submit, one input of 100,000 instructions peaked at 57.1 MiB of
// heap in use (OP_1s dropped), 57.9 (OP_NOPs) and 61.9 (OP_DUPs building a
// stack 100,000 deep), up to 325 bytes an instruction for each verification,
// garbage included. One of 50,000 held 5.9 to 9.9 MiB live (collected at
// 2%, guard_weights_test.go), within what scriptHeadroom reserves, and had
// 67 to 77 MiB in use at the default GOGC, past it (see MemoryBudget). Topic
// managers and lookup services decode the submitted transaction's outputs
// with script.Chunks, 56 bytes a chunk.
//
// Executing a script can hold more than its own bytes only through an opcode
// that writes a new stack element (see scriptcost.Instructions), such as
// OP_CAT doubling an element, and the interpreter's stack memory limit
// (interpreter.DefaultMaxStackMemory, 100,000,000 bytes) bounds that:
// OP_CAT-built stacks held 58.6 to 91 MiB, and a 1,290-byte submit doubling
// a push to 32 MiB peaked at 64.1 MiB.
const (
	// MaxScriptOps caps the instructions of one verified input, its unlocking
	// and spent locking script together, and the chunks of one output
	// script, so that what scriptHeadroom reserves for a BEEF at the cap fits
	// the budget beside its expansion.
	MaxScriptOps = 50_000

	// verifyOpBytes is what one instruction may cost a verification, over
	// the 325 bytes measured.
	verifyOpBytes = 384

	// chunkBytes is what one output chunk may cost, over the 56 measured.
	chunkBytes = 64

	// ExecAllowance is the heap that verifying a script that may write new
	// stack elements can make the interpreter hold: its stack memory limit.
	// The execution slot carries it.
	ExecAllowance int64 = 100 << 20
)

// scriptHeadroom is the heap ReadBody reserves for a BEEF of n bytes beyond
// its expansion: the most scriptWeight can come to for a BEEF that long, since
// every instruction and every chunk takes at least one of its bytes.
func scriptHeadroom(n int64) int64 {
	return 2 * (verifyOpBytes + chunkBytes) * min(n, MaxScriptOps)
}

// scriptWeight is the heap that verifying tx and admitting its outputs may
// hold beyond its BEEF's own expansion, and whether a verified script may
// write new stack elements, which only the execution slot may run; or an
// error wrapping ErrTooComplex when one of its scripts is over MaxScriptOps.
// It walks the transactions spv.Verify runs scripts for: tx and every
// ancestor in the BEEF that has no merkle path.
func scriptWeight(tx *transaction.Transaction) (weight int64, copies bool, err error) {
	var maxOps, maxChunks int
	seen := map[*transaction.Transaction]bool{tx: true}
	queue := []*transaction.Transaction{tx}
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]
		if t != tx && t.MerklePath != nil {
			continue
		}
		for vin, in := range t.Inputs {
			src := in.SourceTransaction
			if src == nil || int(in.SourceTxOutIndex) >= len(src.Outputs) {
				continue // spv.Verify fails here before it parses anything
			}
			ops := 0
			for _, s := range [2]*script.Script{in.UnlockingScript, src.Outputs[in.SourceTxOutIndex].LockingScript} {
				if s == nil {
					continue
				}
				n, c := scriptcost.Instructions(*s, MaxScriptOps)
				ops, copies = ops+n, copies || c
			}
			if ops > MaxScriptOps {
				return 0, false, fmt.Errorf("%w: input %d of %s has over %d script instructions", ErrTooComplex, vin, t.TxID(), MaxScriptOps)
			}
			maxOps = max(maxOps, ops)
			if !seen[src] {
				seen[src] = true
				queue = append(queue, src)
			}
		}
	}
	for vout, out := range tx.Outputs {
		if out == nil || out.LockingScript == nil {
			continue
		}
		n := scriptcost.Chunks(*out.LockingScript, MaxScriptOps)
		if n > MaxScriptOps {
			return 0, false, fmt.Errorf("%w: output %d has over %d script chunks", ErrTooComplex, vout, MaxScriptOps)
		}
		maxChunks = max(maxChunks, n)
	}
	// Two parses of the costliest input (the guard's verification and the
	// engine's) and two decodes of the costliest output (its topic manager's
	// and its lookup service's). A sighash preimage holds a copy of a locking
	// script, which the BEEF's expansion covers.
	return 2 * (int64(maxOps)*verifyOpBytes + int64(maxChunks)*chunkBytes), copies, nil
}
