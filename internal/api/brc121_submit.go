package api

import (
	"context"
	"fmt"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

var brc121SweepSubmitSlots = make(chan struct{}, 1)

// submitBRC121 sends unconfirmed ancestors in dependency order, then the
// payment, under one slot and one time bound. The ARC client returns one
// result for one submitted transaction, so each dependency is sent in its
// own Extended Format request.
func submitBRC121(ctx context.Context, arc *txrelay.ARCClient, p *brc121Payment, sweep bool) (*txrelay.ARCResponse, error) {
	return submitBRC121With(ctx, p, sweep, arc.SubmitContext)
}

func submitBRC121With(ctx context.Context, p *brc121Payment, sweep bool,
	send func(context.Context, []byte) (*txrelay.ARCResponse, error)) (*txrelay.ARCResponse, error) {
	slots := directPaymentSubmitSlots
	if sweep {
		slots = brc121SweepSubmitSlots
	}
	select {
	case slots <- struct{}{}:
	default:
		return nil, errDirectPaymentSubmitsBusy
	}
	defer func() { <-slots }()
	ctx, cancel := context.WithTimeout(ctx, directPaymentSubmitTimeout)
	defer cancel()

	var subject *txrelay.ARCResponse
	for _, tx := range brc121SubmitOrder(p.tx) {
		ef, err := tx.EF()
		if err != nil {
			return nil, fmt.Errorf("build extended format for %s: %w", tx.TxID(), err)
		}
		resp, err := send(ctx, ef)
		if err != nil {
			return resp, fmt.Errorf("ARC broadcast failed: %w", err)
		}
		if err := checkARCAcceptance(resp); err != nil {
			return resp, err
		}
		subject = resp
	}
	return subject, nil
}

func (b *brc121Gate) submitPayment(ctx context.Context, arc *txrelay.ARCClient, p *brc121Payment, sweep bool) (*txrelay.ARCResponse, error) {
	if b.submit != nil {
		return b.submit(ctx, p, sweep)
	}
	return submitBRC121(ctx, arc, p, sweep)
}

func brc121SubmitOrder(subject *transaction.Transaction) []*transaction.Transaction {
	seen := make(map[chainhash.Hash]bool)
	order := make([]*transaction.Transaction, 0, 4)
	var visit func(*transaction.Transaction, bool)
	visit = func(tx *transaction.Transaction, subject bool) {
		if tx == nil || (!subject && tx.MerklePath != nil) {
			return
		}
		id := *tx.TxID()
		if seen[id] {
			return
		}
		seen[id] = true
		if tx.MerklePath == nil {
			for _, input := range tx.Inputs {
				visit(input.SourceTransaction, false)
			}
		}
		order = append(order, tx)
	}
	visit(subject, true)
	return order
}
