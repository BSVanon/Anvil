package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk"
)

// BRC-121 (Simple 402 Payments) lets any BRC-42 wallet pay the node's own
// price for a request. The node's 402 names the price (x-bsv-sats) and the
// node wallet's identity key (x-bsv-server). The payer derives a one-time key
// from that identity key and from values it sends only in its own paid
// request (x-bsv-nonce, x-bsv-time), pays the price to it, broadcasts the
// payment and sends it with the request (x-bsv-beef, x-bsv-sender,
// x-bsv-vout). The node checks that the payment pays its own derivation, has
// the network accept it and records it in the node wallet, which can then
// spend it. The wallet's record is what refuses a payment presented twice.
//
// A BRC-121 payment pays only the node. Checking or spending a payment to a
// derived key takes the recipient's private key, so the node cannot take one
// for an app's key, and it must not hold an app's money: app prices are paid
// with X-Bsv-Payment. What a BRC-121 payment unlocks is node coverage only
// (verifiedPayment.nodeCoverage, nodePriceCovered).

// The BRC-121 headers (BRC-121 section 1; 402-pay constants.ts:10-25).
const (
	headerBRC121Sats   = "x-bsv-sats"
	headerBRC121Server = "x-bsv-server"
	headerBRC121Beef   = "x-bsv-beef"
	headerBRC121Sender = "x-bsv-sender"
	headerBRC121Nonce  = "x-bsv-nonce"
	headerBRC121Time   = "x-bsv-time"
	headerBRC121Vout   = "x-bsv-vout"
)

// brc121Originator is the originator the node's own subsystems give its
// wallet.
const brc121Originator = "anvil"

// brc121ClientShare is how many BRC-121 payments one client may have in
// validation at once, keyed as the node's rate limiter keys it
// (clientKeyFor). A client over its share is answered 503.
const brc121ClientShare = 4

// brc121Wallet is what BRC-121 needs from the node wallet: its identity key
// and the key a payment derives (GetPublicKey), recording a payment
// (InternalizeAction), and whether it already holds a transaction
// (ListTransactions). go-sdk's InternalizeActionResult carries only Accepted
// (wallet/interfaces.go:439-441) and the toolbox wallet drops the storage
// result's isMerge when it maps it, so the wallet's record of the
// transaction is read before the payment is sent to ARC: a transaction it
// already holds is refused there, as BRC-121 refuses an isMerge result
// (section 5, step 5).
type brc121Wallet interface {
	GetPublicKey(ctx context.Context, args sdk.GetPublicKeyArgs, originator string) (*sdk.GetPublicKeyResult, error)
	InternalizeAction(ctx context.Context, args sdk.InternalizeActionArgs, originator string) (*sdk.InternalizeActionResult, error)
	ListTransactions(ctx context.Context, args wdk.ListTransactionsArgs, originator string) (*wdk.ListTransactionsResult, error)
}

// brc121Gate is what the payment gate holds once it takes BRC-121 payments.
type brc121Gate struct {
	wallet    brc121Wallet
	validator *spv.Validator
	server    string           // the node wallet's identity key: x-bsv-server
	now       func() time.Time // the clock x-bsv-time is checked against
	journal   *brc121Journal
	shares    *bodyShares
	counts    brc121Counts
	logger    *slog.Logger
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
}

// enableBRC121 lets pg offer and take BRC-121 payments with the node wallet,
// and starts the journal's sweep (startBRC121). A wallet that cannot report
// the transactions it holds leaves BRC-121 off.
func (pg *PaymentGate) enableBRC121(wallet sdk.Interface, validator *spv.Validator, dataDir string, logger *slog.Logger) error {
	var bw brc121Wallet
	if wallet != nil {
		var ok bool
		if bw, ok = wallet.(brc121Wallet); !ok && pg != nil {
			pg.brc121Off = "the node wallet cannot report the transactions it holds"
			return errors.New(pg.brc121Off)
		}
	}
	return pg.startBRC121(bw, validator, dataDir, logger)
}

// startBRC121 needs the node wallet, an ARC client, the node's SPV validator
// and its data directory; without any of them the gate neither offers nor
// takes BRC-121 and it returns nil. An error leaves BRC-121 off.
func (pg *PaymentGate) startBRC121(bw brc121Wallet, validator *spv.Validator, dataDir string, logger *slog.Logger) error {
	if pg == nil {
		return nil
	}
	switch {
	case bw == nil:
		pg.brc121Off = "no node wallet"
	case pg.arcClient == nil:
		pg.brc121Off = "no ARC client"
	case validator == nil || dataDir == "":
		pg.brc121Off = "no SPV validator or data directory"
	}
	if pg.brc121Off != "" {
		return nil
	}
	pg.brc121Off = "the node wallet could not be set up for BRC-121"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := bw.GetPublicKey(ctx, sdk.GetPublicKeyArgs{IdentityKey: true}, brc121Originator)
	if err != nil {
		return fmt.Errorf("read the node wallet's identity key: %w", err)
	}
	if id == nil || id.PublicKey == nil {
		return errors.New("the node wallet has no identity key")
	}
	journal, err := openBRC121Journal(filepath.Join(dataDir, "brc121-journal"))
	if err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}
	b := &brc121Gate{
		wallet: bw, validator: validator, server: id.PublicKey.ToDERHex(), now: time.Now,
		journal: journal, shares: newBodyShares(brc121ClientShare), logger: logger,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	pg.brc121, pg.brc121Off = b, ""
	go pg.runBRC121Sweep(b)
	return nil
}

// closeBRC121 stops the sweep and closes the journal.
func (pg *PaymentGate) closeBRC121() {
	b := pg.brc121
	if b == nil {
		return
	}
	b.stopOnce.Do(func() {
		close(b.stop)
		<-b.done
		_ = b.journal.close()
	})
}

// brc121Offer is the node price this request's 402 offers to take by BRC-121,
// or 0 when it offers nothing. It offers only when the gate takes BRC-121,
// the request is not token-gated, the node's price for the route is above 0
// and every payee of the challenge is the node's own: an offer that an
// accepted payment could not fully pay would cost a payer whose wallet
// broadcasts before it sends (402-pay client.ts:74-94) money for nothing.
func (pg *PaymentGate) brc121Offer(r *http.Request, payees []Payee, tokenGated bool) int {
	if pg.brc121 == nil || tokenGated || len(payees) == 0 {
		return 0
	}
	node := pg.nodePayee(r.URL.Path)
	if node == nil {
		return 0
	}
	for _, p := range payees {
		if p.Role != node.Role || p.LockingScriptHex != node.LockingScriptHex {
			return 0
		}
	}
	return node.AmountSats
}

// takesBRC121 reports whether r is a BRC-121 payment the gate takes: it
// carries x-bsv-beef, the gate takes BRC-121 and the node prices r's route
// above 0. Otherwise the BRC-121 headers are ignored: a route the node does
// not price is served as if they were absent.
func (pg *PaymentGate) takesBRC121(r *http.Request) bool {
	return pg.brc121 != nil && r.Header.Get(headerBRC121Beef) != "" && pg.nodePayee(r.URL.Path) != nil
}

// serveBRC121 takes r's BRC-121 payment and, once it is recorded, serves r
// with the node coverage it paid. Every refusal is answered by
// writeBRC121Refusal.
func (pg *PaymentGate) serveBRC121(w http.ResponseWriter, r *http.Request, next http.HandlerFunc, payees []Payee, tokenGated bool) {
	b := pg.brc121
	offer := pg.brc121Offer(r, payees, tokenGated)
	if r.Header.Get(HeaderBSVPayment) != "" || r.Header.Get(HeaderX402Proof) != "" {
		b.writeBRC121Refusal(w, r, offer, errBRC121MixedMethods)
		return
	}
	leave, ok := b.shares.take(pg.clientKeyFor(r))
	if !ok {
		b.writeBRC121Refusal(w, r, offer, errBRC121ClientBusy)
		return
	}
	defer leave()
	receipt, err := pg.acceptBRC121(r.Context(), r.Header, pg.nodePayee(r.URL.Path).AmountSats)
	if err != nil {
		b.writeBRC121Refusal(w, r, offer, err)
		return
	}
	b.counts.add(&b.counts.accepted)
	receiptJSON, _ := json.Marshal(receipt)
	w.Header().Set(HeaderX402Receipt, base64Url(receiptJSON))
	// Paid, never authenticated (withPayment, paid_outputs_context.go).
	next(w, r.WithContext(pg.withPayment(r.Context(), receipt)))
}

// brc121Counts counts BRC-121 payments since the node started: offers made,
// payments accepted, refusals by code, journal entries recorded, claimed by
// the sweep, dropped (refused by ARC after they were kept, or expired) and
// refused because the journal was full.
type brc121Counts struct {
	mu                                                   sync.Mutex
	offered, accepted, journaled, claimed, dropped, full uint64
	refusals                                             map[string]uint64
	fullLogged                                           time.Time
}

func (c *brc121Counts) add(n *uint64) {
	c.mu.Lock()
	*n++
	c.mu.Unlock()
}

func (c *brc121Counts) refused(code string) {
	c.mu.Lock()
	if c.refusals == nil {
		c.refusals = make(map[string]uint64)
	}
	c.refusals[code]++
	c.mu.Unlock()
}

// brc121Status is the gate's BRC-121 state for /stats: whether it is offered
// (and why not), the counters, and the journal's size and oldest entry.
func (pg *PaymentGate) brc121Status() map[string]interface{} {
	if pg == nil {
		return map[string]interface{}{"offered": false, "reason": "the node takes no payment"}
	}
	if pg.brc121 == nil {
		return map[string]interface{}{"offered": false, "reason": pg.brc121Off}
	}
	b := pg.brc121
	n, oldest := b.journal.stats(b.now())
	b.counts.mu.Lock()
	defer b.counts.mu.Unlock()
	refusals := make(map[string]uint64, len(b.counts.refusals))
	for k, v := range b.counts.refusals {
		refusals[k] = v
	}
	return map[string]interface{}{
		"offered": true, "offers": b.counts.offered, "accepted": b.counts.accepted, "refused": refusals,
		"journaled": b.counts.journaled, "claimed": b.counts.claimed, "dropped": b.counts.dropped,
		"journal_full_refusals": b.counts.full,
		"journal":               map[string]interface{}{"entries": n, "cap": maxBRC121JournalEntries, "oldest_age_secs": int64(oldest.Seconds())},
	}
}

// compressedKey parses a compressed public key in hex.
func compressedKey(s string) (*ec.PublicKey, error) {
	return ec.PublicKeyFromString(s)
}

// offerBRC121 adds the BRC-121 offer to the 402 challenge it precedes, when
// brc121Offer makes one. The body stays the x402 challenge: BRC-121 asks for
// an empty one (section 2), and the reference client reads only the two
// headers (402-pay client.ts:154-160).
func (pg *PaymentGate) offerBRC121(w http.ResponseWriter, r *http.Request, payees []Payee, tokenGated bool) {
	if sats := pg.brc121Offer(r, payees, tokenGated); sats > 0 {
		pg.brc121.setOffer(w, sats)
		pg.brc121.counts.add(&pg.brc121.counts.offered)
	}
}
