package certgate

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TransactionSource fetches transactions by txid for spend verification.
type TransactionSource interface {
	Tx(context.Context, string) (*transaction.Transaction, error)
}

// SpendVerifier fetches a candidate and the referenced output, confirms the
// input relationship, and executes that input against the output script.
func SpendVerifier(source TransactionSource) func(context.Context, string, string) error {
	return func(ctx context.Context, outpoint, spendingTxid string) error {
		if source == nil {
			return fmt.Errorf("transaction source is unavailable")
		}
		op, err := transaction.OutpointFromString(outpoint)
		if err != nil {
			return fmt.Errorf("invalid revocation outpoint")
		}
		spend, err := source.Tx(ctx, spendingTxid)
		if err != nil || spend == nil || spend.TxID().String() != spendingTxid {
			return fmt.Errorf("fetch candidate spend: %w", err)
		}
		inputIndex := -1
		for i, input := range spend.Inputs {
			if input.SourceTXID != nil && input.SourceTXID.String() == op.Txid.String() && input.SourceTxOutIndex == op.Index {
				inputIndex = i
				break
			}
		}
		if inputIndex < 0 {
			return fmt.Errorf("candidate does not spend revocation outpoint")
		}
		sourceTx, err := source.Tx(ctx, op.Txid.String())
		if err != nil || sourceTx == nil || sourceTx.TxID().String() != op.Txid.String() {
			return fmt.Errorf("fetch revocation transaction: %w", err)
		}
		if int(op.Index) >= len(sourceTx.Outputs) || sourceTx.Outputs[op.Index].LockingScript == nil {
			return fmt.Errorf("revocation output is missing")
		}
		vctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := interpreter.NewEngine().Execute(
			interpreter.WithTx(spend, inputIndex, sourceTx.Outputs[op.Index]),
			interpreter.WithFlags(scriptflag.MainNetActivationHeights.BlockValidationFlags(math.MaxUint32, math.MaxUint32)),
			interpreter.WithContext(vctx),
		); err != nil {
			return fmt.Errorf("candidate spend script failed: %w", err)
		}
		return nil
	}
}
