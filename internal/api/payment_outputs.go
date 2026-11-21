package api

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// matchPayees assigns a distinct transaction output to every requirement.
// An output is consumed by its first match, even when two requirements name
// the same locking script.
func matchPayees(tx *transaction.Transaction, payees []Payee) (int, error) {
	used := make([]bool, len(tx.Outputs))
	total := 0
	for _, payee := range payees {
		if payee.AmountSats < 0 {
			return 0, fmt.Errorf("invalid negative amount for %s payee", payee.Role)
		}
		script, err := hex.DecodeString(payee.LockingScriptHex)
		if err != nil {
			return 0, fmt.Errorf("invalid payee script (%s): %w", payee.Role, err)
		}
		matched := false
		for i, out := range tx.Outputs {
			if used[i] || out.LockingScript == nil || out.Satoshis < uint64(payee.AmountSats) || !bytes.Equal(*out.LockingScript, script) {
				continue
			}
			if out.Satoshis > uint64(math.MaxInt-total) {
				return 0, fmt.Errorf("paid amount is too large to represent")
			}
			used[i] = true
			total += int(out.Satoshis)
			matched = true
			break
		}
		if !matched {
			return 0, fmt.Errorf("no distinct output pays %d sats to %s payee", payee.AmountSats, payee.Role)
		}
	}
	return total, nil
}
