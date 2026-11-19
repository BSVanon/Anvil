package api

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// The nonce mint budget (cold-review round 3, S7).
//
// Every 402 challenge takes a nonce (issueChallengeForPayees). A charging node
// pops one from its UTXONoncePool, which refills from the wallet once it falls
// below a quarter, and mints one on demand when it is empty. A free node, where
// a topic's passthrough or split price makes the challenge, has no pool: it
// mints from the wallet for every challenge (cmd/anvil/main.go). Each mint is a
// wallet transaction that pays a fee and locks 1 sat in the nonce output, and
// asking for a challenge needs no login, so without a bound any caller could
// make the node spend without limit.
//
// One token bucket per process bounds every wallet mint: the pool's on-demand
// mints, its refills, and a free node's direct mints. A mint the budget
// refuses spends nothing, and the challenge is answered 503 with Retry-After.
//
// The numbers. A full bucket allows mintBurst mints at once and refills at
// mintsPerMinute, so in any T minutes the node mints at most
// mintBurst + mintsPerMinute*T nonces: 130 in an hour, then 120 an hour. At
// wallet-toolbox's default fee model, 100 sat/kB rounded up
// (go-wallet-toolbox v0.183.6 defs/fee_model.go, funder/fee_calculator.go), a
// nonce transaction with one P2PKH input, the nonce output and one change
// output is 226 bytes and pays 23 sats; with the toolbox's 8 change outputs
// at most (defs/change_basket.go) it is 464 bytes and 47 sats, and with 3
// inputs as well 760 bytes and 76 sats. So the worst hour costs 130 nonce sats
// and 2,990 sats of fees for typical transactions, or 9,880 sats of fees at
// 76 sats each. A free node mints only for topics an app prices.
//
// A charging node's UTXONoncePool does NOT absorb a burst of up to its own
// size (its poolSize, 100 by default): every mint that fills or refills the
// pool spends from this same budget (nonce_pool.go's replenish and its
// on-demand mint both go through withMintBudget), and filling a pool from
// empty to 100 is itself budget-paced -- the first mintBurst (10) are
// immediate, the remaining 90 trickle in at mintsPerMinute (2), about 45
// minutes, so the pool cannot be relied on to be holding anywhere near 100
// pre-minted nonces unless it has been that idle. The real ceiling a burst
// can rely on is poolSize/4 (25, nonce_pool.go:62's replenish trigger -- the
// level the design assumes a refill is already under way by) plus mintBurst
// (10, this budget's own rested one-shot allowance, wherever it is spent
// from: replenish's loop, the on-demand path once the pool is empty, or
// both): about 35, checked against a frozen clock, which a tight burst
// effectively is against this budget's 30 s interval -- a rested mintBudget
// grants exactly mintBurst mints before every further take() fails, and
// take() is serialized by the budget's own mutex regardless of which caller
// reaches it. A pool caught fuller than its 25 design floor, from unusually
// long idle time beforehand, can briefly absorb more; that is a bonus the
// design does not rely on, not a guarantee.
const (
	mintBurst      = 10
	mintsPerMinute = 2
)

// defaultMintBudget is the process-wide budget that NewUTXONoncePool and
// NewPaymentGate apply.
var defaultMintBudget = newMintBudget(mintBurst, mintsPerMinute, time.Now)

// mintBudget is a token bucket of nonce mints, kept as the time its next mint
// is due (the generic cell rate algorithm), so that it counts in whole
// durations, never in fractions of a token. It is safe for concurrent use.
type mintBudget struct {
	mu       sync.Mutex
	now      func() time.Time
	interval time.Duration // the time that earns back one mint
	slack    time.Duration // interval*(burst-1): how far ahead of now due may run
	due      time.Time     // when the next mint is due at the sustained rate
}

// newMintBudget returns a full bucket of burst mints that refills at
// perMinute mints a minute, reading the time from now. burst and perMinute
// must be at least 1.
func newMintBudget(burst, perMinute int, now func() time.Time) *mintBudget {
	interval := time.Minute / time.Duration(perMinute)
	return &mintBudget{
		now:      now,
		interval: interval,
		slack:    interval * time.Duration(burst-1),
		due:      now(),
	}
}

// take spends one mint. When none is left it spends nothing and returns how
// long until one is.
func (b *mintBudget) take() (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	due := b.due
	if due.Before(now) {
		due = now
	}
	if ahead := due.Sub(now); ahead > b.slack {
		return false, ahead - b.slack
	}
	b.due = due.Add(b.interval)
	return true, 0
}

// mintBudgetError is MintNonce's error when the budget has no mint left.
type mintBudgetError struct {
	retryAfter time.Duration
}

func (e *mintBudgetError) Error() string {
	return fmt.Sprintf("nonce mint budget spent, next mint in %s", e.retryAfter.Round(time.Second))
}

// budgetedNonceProvider mints from inner only when budget allows it.
type budgetedNonceProvider struct {
	inner  NonceProvider
	budget *mintBudget
}

// MintNonce spends one mint from the budget and mints, or returns a
// *mintBudgetError without calling inner. A mint that inner fails still
// spends its token, since a failed wallet action may already have paid.
func (p *budgetedNonceProvider) MintNonce() (*NonceUTXO, error) {
	if ok, wait := p.budget.take(); !ok {
		return nil, &mintBudgetError{retryAfter: wait}
	}
	return p.inner.MintNonce()
}

// costFreeNonces is implemented by nonce providers whose mints spend nothing,
// so no budget applies to them. Only DevNonceProvider, which mints no real
// UTXO, is one.
type costFreeNonces interface {
	noncesCostNothing()
}

func (*DevNonceProvider) noncesCostNothing() {}

// withMintBudget returns p behind budget, unless p's mints cost nothing, p is
// budgeted already, or p is a UTXONoncePool, which budgets its own mints.
func withMintBudget(p NonceProvider, budget *mintBudget) NonceProvider {
	switch p.(type) {
	case nil, costFreeNonces, *budgetedNonceProvider, *UTXONoncePool:
		return p
	}
	return &budgetedNonceProvider{inner: p, budget: budget}
}

// writeUnavailable answers 503 with a Retry-After of at least one second.
func writeUnavailable(w http.ResponseWriter, retryAfter time.Duration, msg string) {
	secs := int64(math.Ceil(retryAfter.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	writeError(w, http.StatusServiceUnavailable, msg)
}
