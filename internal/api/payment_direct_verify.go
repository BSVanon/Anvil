package api

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// maxDirectPaymentInputs caps how many inputs verifyDirectPaymentInputs will
// verify on one X-Bsv-Payment transaction. Each input runs the same
// checkNonceUnlockingScript + runNonceScripts pair the challenge-proof
// nonce spend uses (payment_bounds.go), bounded at nonceScriptTimeout (2s)
// and a push-only P2PKH shape. A typical x402 micropayment spends one or a
// few inputs; 10 bounds the worst case at 10 * nonceScriptTimeout (20s)
// while leaving headroom for a wallet that coalesces several small UTXOs.
// Without this cap, maxPaymentHeaderBytes (256 KiB) alone would still allow
// several thousand minimal inputs in one transaction.
const maxDirectPaymentInputs = 10

// errDirectPaymentUnverifiable marks a direct-payment transaction (or one of
// its inputs) that verifyDirectPaymentInputs refuses to accept without
// running the interpreter against it. It carries a stable code
// (codeDirectPaymentUnverifiable, payment_refusal.go), which every refusal
// wrapping it is answered with.
var errDirectPaymentUnverifiable = &paymentRefusal{
	code: codeDirectPaymentUnverifiable,
	msg:  "direct payment cannot be verified",
}

// verifyDirectPaymentInputs checks that every input of tx is a genuine,
// signature-verified P2PKH spend of the source output the client supplied,
// the same way the challenge-proof flow verifies its nonce input
// (verifyNonceInputSignature, payment_verify.go): go-sdk's own script
// interpreter, behind payment_bounds.go's checkNonceUnlockingScript and
// runNonceScripts, never a hand-rolled check.
//
// Each input must carry the output it spends, as every input of an Extended
// Format (BRC-30) transaction does. An input without one is refused as
// unverifiable rather than trusted, so a plain raw transaction is refused.
// Atomic BEEF is not parsed. The check proves that the signatures match the
// outputs the client supplied, not that those outputs exist; ARC's
// acceptance, which verifyDirectPayment requires, shows that.
//
// The locking script must also be exactly P2PKH, as on the nonce path: it
// comes from the payer's own claim, with nothing on-chain to check it
// against here, and an arbitrary, unbounded script run through the
// interpreter on this no-login endpoint would let any caller spend the
// node's CPU and memory. P2PKH's fixed shape leaves no such room.
func verifyDirectPaymentInputs(tx *transaction.Transaction) error {
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("%w: no inputs", errDirectPaymentUnverifiable)
	}
	if len(tx.Inputs) > maxDirectPaymentInputs {
		return fmt.Errorf("%w: %d inputs, the most a direct payment verifies is %d",
			errDirectPaymentUnverifiable, len(tx.Inputs), maxDirectPaymentInputs)
	}
	for i, input := range tx.Inputs {
		out := input.SourceTxOutput()
		if out == nil {
			return fmt.Errorf("%w: input %d does not carry the output it spends (send the transaction in Extended Format, BRC-30)",
				errDirectPaymentUnverifiable, i)
		}
		if out.LockingScript == nil {
			return fmt.Errorf("%w: input %d's source output has no locking script", errDirectPaymentUnverifiable, i)
		}
		if input.UnlockingScript == nil || len(*input.UnlockingScript) == 0 {
			return fmt.Errorf("%w: input %d has no unlocking script", errDirectPaymentUnverifiable, i)
		}
		if err := checkNonceUnlockingScript(out.LockingScript, input.UnlockingScript); err != nil {
			return fmt.Errorf("input %d: %w", i, err)
		}
		if err := runNonceScripts(tx, i, out); err != nil {
			return fmt.Errorf("input %d script execution failed: %w", i, err)
		}
	}
	return nil
}
