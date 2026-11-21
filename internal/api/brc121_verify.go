package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk"
)

// The wallet's record of a payment: a fixed description and label, with
// nothing from the request, so the wallet holds no log of who asked for
// what. The reference middleware puts the request path in its description
// (402-pay server.ts:168); BRC-121 does not ask for it.
const (
	brc121Description = "BRC-121 payment"
	brc121Label       = "brc121 payment"
)

// brc121RecordTimeout bounds recording a payment the network has accepted. It
// runs on a context the client's disconnect does not end, so a payment ARC
// accepted is recorded whether or not its payer is still waiting.
const brc121RecordTimeout = 30 * time.Second

// acceptBRC121 takes the BRC-121 payment in h for a node price of price, in
// order: the headers (readBRC121Headers), the BEEF (readBRC121BEEF), the
// derivation (checkDerivation), the input scripts (verifyDirectPaymentInputs)
// and the BEEF's proofs against this node's headers (spv ValidateBEEF), the
// replay claim, the wallet's own record of the transaction, ARC, and the
// wallet recording it. Nothing is sent to ARC or stored before the payment
// is shown to pay this node's own derivation. A payment that passes the
// checks but is not recorded is kept in the journal (brc121_journal.go)
// unless ARC refused it outright: its payer has already broadcast it.
func (pg *PaymentGate) acceptBRC121(ctx context.Context, h http.Header, price int) (*X402Receipt, error) {
	b := pg.brc121
	p, beef, err := readBRC121Headers(h, b.now())
	if err != nil {
		return nil, err
	}
	if err := p.readBRC121BEEF(beef, price); err != nil {
		return nil, err
	}
	if err := b.checkDerivation(ctx, p); err != nil {
		return nil, err
	}
	if err := verifyDirectPaymentInputs(p.tx); err != nil {
		return nil, brc121Refuse(codeBRC121Unverifiable, err.Error())
	}
	if err := b.verifyProofs(ctx, p.atomic); err != nil {
		return nil, err
	}

	// One transaction pays for one request, on every payment path
	// (payment_replay.go); the claim is kept only for a recorded payment.
	if !pg.replays.begin(p.txid) {
		return nil, brc121Refuse(codeBRC121Replayed, errPaymentReplayed(p.txid.String()).Error())
	}
	recorded := false
	defer func() { pg.replays.end(p.txid, recorded) }()
	held, err := b.walletHolds(ctx, p.txid.String())
	if err != nil {
		b.keep(p)
		return nil, errBRC121Wallet(fmt.Sprintf("the node wallet could not read its records: %v", err))
	}
	if held {
		return nil, brc121Refuse(codeBRC121Replayed, fmt.Sprintf("payment %s is already in the node wallet", p.txid))
	}

	if err := pg.brc121Network(ctx, p); err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), brc121RecordTimeout)
	defer cancel()
	if err := b.record(rctx, p); err != nil {
		b.keep(p)
		return nil, brc121Refuse(codeBRC121NotAccepted, fmt.Sprintf("the node wallet did not record payment %s: %v; the node keeps it and records it later", p.txid, err))
	}
	recorded = true
	b.journal.remove(p.txid.String())
	return &X402Receipt{
		TxID:         p.txid.String(),
		Satoshis:     int(p.sats),
		Timestamp:    b.now().Unix(),
		nodeCoverage: p.sats,
	}, nil
}

// verifyProofs refuses a BEEF whose proofs do not verify against this node's
// headers (spv.Validator.ValidateBEEF, as /wallet/internalize checks it).
// ValidateBEEF checks the BEEF's structure and merkle roots, not scripts:
// verifyDirectPaymentInputs runs the subject's, and the toolbox runs every
// unmined transaction's when it records the payment
// (internalize.go:111-130). A BEEF with no proof at all is refused too: the
// toolbox's own verification of it (internalize.go:98-104) fails, so the
// wallet could never record it.
func (b *brc121Gate) verifyProofs(ctx context.Context, atomic []byte) error {
	res, err := b.validator.ValidateBEEF(ctx, atomic)
	if err != nil || res == nil || !res.Valid || res.Confidence == spv.ConfidenceInvalid || res.Confidence == spv.ConfidenceUnconfirmed {
		msg := "no result"
		if err != nil {
			msg = err.Error()
		} else if res != nil {
			msg = res.Message
		}
		return brc121Refuse(codeBRC121Unverifiable, "the payment's BEEF does not verify against this node's headers: "+msg)
	}
	return nil
}

// walletHolds reports whether the node wallet already holds txid: the
// record InternalizeAction's isMerge reads (internalize.go:151-156), which
// ListTransactions filters the same transactions table by
// (storage/provider.go:1045-1048).
func (b *brc121Gate) walletHolds(ctx context.Context, txid string) (bool, error) {
	res, err := b.wallet.ListTransactions(ctx, wdk.ListTransactionsArgs{TxIDs: []string{txid}, Limit: 1}, brc121Originator)
	if err != nil {
		return false, err
	}
	return res != nil && (res.TotalTransactions > 0 || len(res.Transactions) > 0), nil
}

// brc121Network sends p to ARC in Extended Format (BRC-30), the format the
// X-Bsv-Payment path submits, built from the BEEF's source transactions,
// through the same submit cap and time bound (submitDirectPayment). It
// returns nil once ARC reports the payment accepted and within the node's
// depth bound (checkARCAcceptance, checkPaymentDepth). A payment ARC did not
// accept is kept for the sweep unless ARC refused it outright
// (arcRefusedOutright).
func (pg *PaymentGate) brc121Network(ctx context.Context, p *brc121Payment) error {
	b := pg.brc121
	ef, err := p.tx.EF()
	if err != nil {
		return brc121Refuse(codeBRC121BadBEEF, fmt.Sprintf("build the payment's extended format: %v", err))
	}
	resp, err := submitDirectPayment(ctx, pg.arcClient, ef)
	if errors.Is(err, errDirectPaymentSubmitsBusy) {
		b.keep(p)
		return errBRC121SubmitsBusy
	}
	if err == nil {
		err = checkARCAcceptance(resp)
	}
	if err != nil {
		if !arcRefusedOutright(resp, err) {
			b.keep(p)
		}
		return brc121Refuse(codeBRC121NotAccepted, fmt.Sprintf("the network did not accept payment %s: %v", p.txid, err))
	}
	if err := pg.checkPaymentDepth(resp); err != nil {
		b.keep(p)
		return brc121Refuse(codeBRC121NotAccepted, err.Error())
	}
	return nil
}

// record internalizes p in the node wallet as a wallet payment (BRC-121
// section 5, step 4): the subject's closure as an Atomic BEEF, output vout,
// and the remittance the toolbox derives the key from. go-sdk's Payment holds
// the prefix and suffix as bytes, which the toolbox encodes as base64 to make
// the key ID (mapping_internalize_action.go:46-63), so the prefix is the
// nonce decoded and the suffix the time's own bytes.
func (b *brc121Gate) record(ctx context.Context, p *brc121Payment) error {
	prefix, err := base64.StdEncoding.DecodeString(p.nonce)
	if err != nil {
		return err
	}
	res, err := b.wallet.InternalizeAction(ctx, sdk.InternalizeActionArgs{
		Tx:          p.atomic,
		Description: brc121Description,
		Labels:      []string{brc121Label},
		Outputs: []sdk.InternalizeOutput{{
			OutputIndex: p.vout,
			Protocol:    sdk.InternalizeProtocolWalletPayment,
			PaymentRemittance: &sdk.Payment{
				DerivationPrefix:  prefix,
				DerivationSuffix:  []byte(p.time),
				SenderIdentityKey: p.sender,
			},
		}},
	}, brc121Originator)
	if err != nil {
		return err
	}
	if res == nil || !res.Accepted {
		return errors.New("the wallet did not accept it")
	}
	return nil
}

// ARC's outright refusals of a transaction: its answers that this
// transaction will not be accepted as sent, so a payment refused with one is
// not kept for the sweep. Anything else (no answer, a timeout, a status
// still on its way, an error about the request rather than the
// transaction) may still end with the payment accepted, so it is kept.
//
// The statuses are the ones go-sdk's ARC broadcaster treats as failures
// (transaction/broadcaster/arc.go:190-196, with any ORPHAN status at
// 218-225), less MINED_IN_STALE_BLOCK, whose transaction is mined again. The
// toolbox's problematic statuses (services/internal/arc/tx_status.go:42-44)
// add UNKNOWN, which is kept: it says nothing about the transaction.
// The HTTP statuses are ARC's codes for an invalid transaction
// (pkg/api/status.go:14-31 and 53-120): unlocking scripts (461), inputs
// missing or spent (462), malformed (463), outputs (464), fee too low (465),
// conflicting (466), frozen inputs (471, 472), cumulative fee (473) and size
// (474). 460 (not extended format), 468 (invalid BEEF), 469 (merkle roots)
// and 475 (mined ancestors without a BUMP) are about the form the node sent,
// and are retried.
var (
	arcRefusedStatuses = map[string]bool{"REJECTED": true, "DOUBLE_SPEND_ATTEMPTED": true, "SEEN_IN_ORPHAN_MEMPOOL": true, "INVALID": true, "MALFORMED": true}
	arcRefusedHTTP     = map[int]bool{461: true, 462: true, 463: true, 464: true, 465: true, 466: true, 471: true, 472: true, 473: true, 474: true}
)

// arcRefusedOutright reports whether ARC's answer (resp, or the error err
// from the submit) refuses the transaction outright.
func arcRefusedOutright(resp *txrelay.ARCResponse, err error) bool {
	var httpErr *txrelay.ARCHTTPError
	if errors.As(err, &httpErr) {
		return arcRefusedHTTP[httpErr.StatusCode]
	}
	return resp != nil && arcRefusedStatuses[resp.Status]
}
