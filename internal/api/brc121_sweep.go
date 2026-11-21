package api

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const (
	// brc121SweepEvery is how often the sweep runs.
	brc121SweepEvery = 2 * time.Minute
	// brc121SweepMinAge is how long an entry waits before the sweep tries
	// it. It is past the payment's own 30-second window, so the sweep never
	// races its payer retrying the same payment.
	brc121SweepMinAge = time.Minute
)

// runBRC121Sweep runs the sweep every brc121SweepEvery until the gate's BRC-121
// is closed. It serves nothing.
func (pg *PaymentGate) runBRC121Sweep(b *brc121Gate) {
	defer close(b.done)
	t := time.NewTicker(brc121SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-t.C:
			pg.sweepBRC121(context.Background())
		}
	}
}

// sweepBRC121 tries each journal entry at least brc121SweepMinAge old, oldest
// first and one at a time: an entry past brc121JournalTTL is dropped and
// counted, with only its txid logged; otherwise it is sent to ARC again,
// through the sweep's reserved submit slot. Accepted or mined, it is recorded in the node
// wallet, which takes a transaction it already holds as a merge, and the
// entry is deleted. Refused outright (arcRefusedOutright), the entry is
// deleted. Anything else keeps it for the next sweep, and a full submit cap
// ends this one.
func (pg *PaymentGate) sweepBRC121(ctx context.Context) {
	b := pg.brc121
	now := b.now()
	for _, txid := range b.journal.due(now.Add(-brc121SweepMinAge)) {
		if ctx.Err() != nil {
			return
		}
		e, err := b.journal.get(txid)
		if err != nil {
			b.logger.Error("BRC-121 journal read failed", "txid", txid, "error", err)
			continue
		}
		if now.Sub(time.Unix(e.Kept, 0)) > brc121JournalTTL {
			b.drop(txid)
			b.counts.add(&b.counts.dropped)
			b.logger.Warn("BRC-121 journal entry expired unclaimed", "txid", txid)
			continue
		}
		if busy := pg.sweepEntry(ctx, e); busy {
			return
		}
	}
}

// sweepEntry tries one entry, under the replay claim, so it never races a
// request presenting the same payment. It reports whether the submit cap was
// full.
func (pg *PaymentGate) sweepEntry(ctx context.Context, e *brc121Entry) (busy bool) {
	b := pg.brc121
	p, err := e.payment()
	if err != nil {
		b.drop(e.TxID)
		b.counts.add(&b.counts.dropped)
		b.logger.Error("BRC-121 journal entry unreadable, dropped", "txid", e.TxID, "error", err)
		return false
	}
	if !pg.replays.begin(p.txid) {
		return false
	}
	recorded := false
	defer func() { pg.replays.end(p.txid, recorded) }()
	resp, err := b.submitPayment(ctx, pg.arcClient, p, true)
	if errors.Is(err, errDirectPaymentSubmitsBusy) {
		return true
	}
	if err != nil {
		if arcRefusedOutright(resp, err) {
			b.drop(e.TxID)
			b.counts.add(&b.counts.dropped)
			b.logger.Info("BRC-121 kept payment refused by the network, dropped", "txid", e.TxID)
		}
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, brc121RecordTimeout)
	defer cancel()
	if err := b.record(rctx, p); err != nil {
		b.logger.Warn("BRC-121 kept payment not yet recorded", "txid", e.TxID, "error", err)
		return false
	}
	recorded = true
	b.drop(e.TxID)
	b.counts.add(&b.counts.claimed)
	return false
}

// payment rebuilds the payment an entry kept.
func (e *brc121Entry) payment() (*brc121Payment, error) {
	beef, subject, err := transaction.NewBeefFromAtomicBytes(e.BEEF)
	if err != nil {
		return nil, err
	}
	tx := beef.FindAtomicTransactionByHash(subject)
	if tx == nil || subject.String() != e.TxID {
		return nil, errors.New("the kept BEEF does not hold its payment")
	}
	raw, err := hex.DecodeString(e.Sender)
	if err != nil {
		return nil, err
	}
	sender, err := ec.PublicKeyFromBytes(raw)
	if err != nil {
		return nil, err
	}
	return &brc121Payment{
		sender: sender, nonce: e.Nonce, time: e.Time, vout: e.Vout,
		tx: tx, txid: chainhash.Hash(*subject), atomic: e.BEEF, sats: e.Satoshis,
	}, nil
}
