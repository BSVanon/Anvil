package ordtrack

import (
	"context"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

var (
	// errNotOneSat means the outpoint is not a 1-sat output, so it is in no
	// token chain.
	errNotOneSat = errors.New("not a 1-sat output")
	// errWalkTooLong means the backward walk needs more hops than allowed.
	errWalkTooLong = errors.New("backward walk exceeds its hop limit")
)

// loadFunc returns the transaction with txid. What it returns must hash to
// txid, as Source.Tx's results do.
type loadFunc func(ctx context.Context, txid string) (*transaction.Transaction, error)

// proveOrigin walks backward from outpoint as BRC-159's "Finding origin from
// an outpoint" does, and returns the origin: the first outpoint from which
// the walk cannot go on as a 1-to-1 hop. It refuses a transaction with more
// than maxInputs inputs and a walk of more than maxHops hops, so with
// maxHops 0 it succeeds only when outpoint is itself an origin.
func proveOrigin(ctx context.Context, outpoint string, load loadFunc, maxHops int) (string, error) {
	current := outpoint
	for hops := 0; ; hops++ {
		txid, vout, ok := splitOutpoint(current)
		if !ok {
			return "", fmt.Errorf("invalid outpoint %q", current)
		}
		tx, err := load(ctx, txid)
		if err != nil {
			return "", err
		}
		if int(vout) >= len(tx.Outputs) || tx.Outputs[vout].Satoshis != 1 {
			return "", errNotOneSat
		}
		if len(tx.Inputs) > maxInputs {
			return "", fmt.Errorf("%s has %d inputs, more than %d", txid, len(tx.Inputs), maxInputs)
		}
		var outAcc uint64
		for _, o := range tx.Outputs[:vout] {
			outAcc = saturatingAdd(outAcc, o.Satoshis)
		}
		prev, moved, err := coveringOneSatInput(ctx, tx, outAcc, load)
		if err != nil {
			return "", err
		}
		if !moved {
			return current, nil
		}
		if hops >= maxHops {
			return "", errWalkTooLong
		}
		current = prev
	}
}

// coveringOneSatInput finds the input covering the sat at position outAcc+1
// in tx's outputs, and reports whether it is a 1-sat input whose own sat
// sits exactly there, which makes the hop a 1-to-1 transfer.
func coveringOneSatInput(ctx context.Context, tx *transaction.Transaction, outAcc uint64, load loadFunc) (prev string, moved bool, err error) {
	var inAcc uint64
	for _, in := range tx.Inputs {
		if in.SourceTXID == nil {
			return "", false, nil
		}
		src, err := load(ctx, in.SourceTXID.String())
		if err != nil {
			return "", false, err
		}
		if int(in.SourceTxOutIndex) >= len(src.Outputs) {
			return "", false, fmt.Errorf("input spends missing output %d of %s", in.SourceTxOutIndex, in.SourceTXID)
		}
		inSats := src.Outputs[in.SourceTxOutIndex].Satoshis
		if saturatingAdd(inAcc, inSats) <= outAcc {
			inAcc += inSats
			continue
		}
		if inSats == 1 && inAcc == outAcc {
			return outpointString(in.SourceTXID.String(), in.SourceTxOutIndex), true, nil
		}
		return "", false, nil
	}
	return "", false, nil
}
