package api

import (
	"errors"
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
// running the interpreter against it.
var errDirectPaymentUnverifiable = errors.New("direct payment cannot be verified")

// verifyDirectPaymentInputs checks that every input of tx is a genuine,
// signature-verified P2PKH spend — the same way the challenge-proof flow's
// nonce input is verified (verifyNonceInputSignature, payment_verify.go),
// using go-sdk's own script interpreter (payment_bounds.go's
// checkNonceUnlockingScript + runNonceScripts), never a hand-rolled one.
//
// Before this check, verifyDirectPayment (X-Bsv-Payment, no challenge-nonce
// binding) accepted any transaction whose OUTPUTS matched the required
// payees, with no check at all that its INPUTS were validly signed. When no
// ARC client was configured — so nothing downstream would implicitly reject
// an invalid transaction at broadcast time either — a wholly unsigned
// transaction was served exactly like a real payment.
//
// Each input must carry its own spent output embedded (extended
// format/BEEF — HeaderBSVPayment's doc comment, payment.go, already
// documents "Atomic BEEF format"), the same way the challenge-proof flow
// already knows the nonce output it is checking against: an input with no
// embedded source output is refused as unverifiable rather than silently
// trusted, and a plain/legacy-format transaction (no inputs carry one) is
// refused outright. This is a narrowing of what X-Bsv-Payment accepts — a
// plain raw transaction with no embedded previous-output data used to be
// accepted (with zero script verification either way) and now is not.
//
// The locking script side must also be exactly P2PKH, same as the nonce
// path: it comes from the payer's own claim with nothing on-chain to check
// it against here, so letting an attacker choose an arbitrary, unbounded
// locking script to run through the interpreter on this no-login endpoint
// would reopen the same script-heap/CPU-bomb class cold review rounds 3-4
// found for other unauthenticated script-execution paths. P2PKH's fixed
// shape leaves no such room.
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
			return fmt.Errorf("%w: input %d carries no embedded source output (extended format/BEEF required)",
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
