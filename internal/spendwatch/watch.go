// Package spendwatch watches a bounded set of outpoints and reports
// candidate spends of them to the subsystems that asked (each an "owner").
//
// A spend is learned from three sources, cheapest first:
//
//  1. Observe: every transaction this node broadcasts or relays is checked
//     against the watched set, one map lookup per input.
//  2. Hint: a peer's claim that an outpoint was spent by a given txid.
//  3. A poll of WhatsOnChain's spent-output endpoint for each watched
//     outpoint, every PollInterval with ±20% jitter, all requests through
//     one global limiter (1 request/s by default) that backs off on a 429.
//
// It never scans P2P blocks or the mempool for spends: finding a spend that
// way means reading every transaction the network carries, a cost that grows
// with the whole chain rather than with the few outpoints being watched.
//
// A reported spending txid is only a candidate. Nothing here checks that the
// transaction exists, is valid or spends the outpoint; owners verify it.
package spendwatch

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Defaults and fixed bounds.
const (
	DefaultPollInterval = 10 * time.Minute
	DefaultMaxWatched   = 10000
	defaultRequestGap   = time.Second // the global 1 request/s cap
	defaultBackoffBase  = 5 * time.Second
	defaultBackoffMax   = 5 * time.Minute
	pollJitter          = 0.2
	// unspentTTL is how long Check trusts an unspent answer, or a spend
	// WhatsOnChain does not yet report as confirmed. A confirmed spend is
	// kept for good.
	unspentTTL = 5 * time.Minute
	// maxCached bounds Check's cache. Past it the oldest answer is dropped;
	// a dropped answer is only looked up again.
	maxCached = 50000
)

// ErrFull is returned by Watch when the watched set is at its cap.
var ErrFull = errors.New("spend watch is at its cap of watched outpoints")

// Config configures a Watcher. Zero values take the defaults.
type Config struct {
	PollInterval time.Duration
	MaxWatched   int
	// WoCBase is the WhatsOnChain API base, ending in the network
	// (default https://api.whatsonchain.com/v1/bsv/main).
	WoCBase    string
	HTTPClient *http.Client
	// RequestGap is the least time between two WhatsOnChain requests.
	RequestGap  time.Duration
	BackoffBase time.Duration
	BackoffMax  time.Duration
	Logger      *slog.Logger
}

// Watcher is a generic spend watcher. Its methods are safe for concurrent
// use. Callbacks run on the caller's goroutine (Observe's, Hint's or the
// poll loop's) and must not block.
type Watcher struct {
	interval time.Duration
	max      int
	woc      *wocClient
	logger   *slog.Logger
	jitter   func() float64 // in [0, 1)

	mu        sync.Mutex
	watched   map[string]*watch
	callbacks map[string]func(outpoint, spendingTxid string)
	cache     map[string]cached
	cacheKeys []string // insertion order, for the cache's bound
	wake      chan struct{}

	polls      atomic.Int64
	pollErrors atomic.Int64
}

type watch struct {
	txid   string
	vout   uint32
	owners map[string]struct{}
	due    time.Time
}

type cached struct {
	ans     answer
	expires time.Time // zero: kept for good
}

// New returns a Watcher. Run starts its poll loop.
func New(cfg Config) *Watcher {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.MaxWatched <= 0 {
		cfg.MaxWatched = DefaultMaxWatched
	}
	if cfg.WoCBase == "" {
		cfg.WoCBase = defaultWoCBase
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.RequestGap <= 0 {
		cfg.RequestGap = defaultRequestGap
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = defaultBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = defaultBackoffMax
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Watcher{
		interval: cfg.PollInterval,
		max:      cfg.MaxWatched,
		woc: &wocClient{
			base:   strings.TrimRight(cfg.WoCBase, "/"),
			client: cfg.HTTPClient,
			lim:    &limiter{gap: cfg.RequestGap, backoffBase: cfg.BackoffBase, backoffMax: cfg.BackoffMax},
		},
		logger:    cfg.Logger,
		jitter:    rand.Float64,
		watched:   make(map[string]*watch),
		callbacks: make(map[string]func(string, string)),
		cache:     make(map[string]cached),
		wake:      make(chan struct{}, 1),
	}
}

// OnSpent registers owner's callback, replacing any earlier one. It is
// called with a watched outpoint ("txid_vout") and a candidate spending txid.
func (w *Watcher) OnSpent(owner string, fn func(outpoint, spendingTxid string)) {
	w.mu.Lock()
	w.callbacks[owner] = fn
	w.mu.Unlock()
}

// Watch adds outpoint ("txid_vout" or "txid.vout") to owner's watched set.
// Its first poll comes one jittered interval later; call Check for an
// answer now.
func (w *Watcher) Watch(outpoint, owner string) error {
	key, txid, vout, ok := normalize(outpoint)
	if !ok {
		return errors.New("invalid outpoint")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if e, ok := w.watched[key]; ok {
		e.owners[owner] = struct{}{}
		return nil
	}
	if len(w.watched) >= w.max {
		return ErrFull
	}
	w.watched[key] = &watch{txid: txid, vout: vout, owners: map[string]struct{}{owner: {}}, due: w.nextDue(time.Now())}
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return nil
}

// Unwatch removes outpoint from owner's watched set. An outpoint no owner
// watches is no longer polled.
func (w *Watcher) Unwatch(outpoint, owner string) {
	key, _, _, ok := normalize(outpoint)
	if !ok {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if e, ok := w.watched[key]; ok {
		delete(e.owners, owner)
		if len(e.owners) == 0 {
			delete(w.watched, key)
		}
	}
}

// Len returns how many outpoints are watched.
func (w *Watcher) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.watched)
}

// Observe checks a transaction this node broadcast or relayed against the
// watched set: source 1.
func (w *Watcher) Observe(tx *transaction.Transaction) {
	if tx == nil || w.Len() == 0 {
		return
	}
	var hits []string
	w.mu.Lock()
	for _, in := range tx.Inputs {
		if in.SourceTXID == nil {
			continue
		}
		key := in.SourceTXID.String() + "_" + strconv.FormatUint(uint64(in.SourceTxOutIndex), 10)
		if _, ok := w.watched[key]; ok {
			hits = append(hits, key)
		}
	}
	w.mu.Unlock()
	if len(hits) == 0 {
		return
	}
	txid := tx.TxID().String()
	for _, key := range hits {
		w.dispatch(key, txid)
	}
}

// Hint reports a peer's claim that spendingTxid spends outpoint: source 2.
// It reaches owners only when outpoint is watched.
func (w *Watcher) Hint(outpoint, spendingTxid string) {
	key, _, _, ok := normalize(outpoint)
	if !ok || !isTxid(spendingTxid) {
		return
	}
	w.dispatch(key, strings.ToLower(spendingTxid))
}

// Check asks whether outpoint is spent, now, through the same limiter as the
// poll. An unspent answer is cached for 5 minutes, a confirmed spend for
// good.
func (w *Watcher) Check(ctx context.Context, outpoint string) (spent bool, spendingTxid string, err error) {
	key, txid, vout, ok := normalize(outpoint)
	if !ok {
		return false, "", errors.New("invalid outpoint")
	}
	w.mu.Lock()
	c, hit := w.cache[key]
	w.mu.Unlock()
	if hit && (c.expires.IsZero() || time.Now().Before(c.expires)) {
		return c.ans.spent, c.ans.txid, nil
	}
	ans, err := w.woc.spent(ctx, txid, vout)
	if err != nil {
		return false, "", err
	}
	w.remember(key, ans)
	return ans.spent, ans.txid, nil
}

// Stats returns how many polls ran and how many of them failed.
func (w *Watcher) Stats() (polls, pollErrors int64) {
	return w.polls.Load(), w.pollErrors.Load()
}

// Run polls watched outpoints as they come due, until ctx is done: source 3.
func (w *Watcher) Run(ctx context.Context) {
	for {
		key, txid, vout, wait := w.takeDue(time.Now())
		if key == "" {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-w.wake:
				t.Stop()
			case <-t.C:
			}
			continue
		}
		ans, err := w.woc.spent(ctx, txid, vout)
		if ctx.Err() != nil {
			return
		}
		w.polls.Add(1)
		if err != nil {
			w.pollErrors.Add(1)
			w.logger.Debug("spend poll failed", "outpoint", key, "error", err)
			continue
		}
		w.remember(key, ans)
		if ans.spent {
			w.dispatch(key, ans.txid)
		}
	}
}

// takeDue returns the watched outpoint that has waited longest past its due
// time, already rescheduled one jittered interval on, or how long until the
// next one is due.
func (w *Watcher) takeDue(now time.Time) (key, txid string, vout uint32, wait time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var best *watch
	for k, e := range w.watched {
		if best == nil || e.due.Before(best.due) {
			best, key = e, k
		}
	}
	if best == nil {
		return "", "", 0, w.interval
	}
	if best.due.After(now) {
		return "", "", 0, best.due.Sub(now)
	}
	best.due = w.nextDue(now)
	return key, best.txid, best.vout, 0
}

// nextDue is one interval after now, jittered by ±20%.
func (w *Watcher) nextDue(now time.Time) time.Time {
	f := 1 - pollJitter + 2*pollJitter*w.jitter()
	return now.Add(time.Duration(float64(w.interval) * f))
}

// dispatch calls the callback of every owner watching key.
func (w *Watcher) dispatch(key, spendingTxid string) {
	w.mu.Lock()
	e, ok := w.watched[key]
	var fns []func(string, string)
	if ok {
		for owner := range e.owners {
			if fn := w.callbacks[owner]; fn != nil {
				fns = append(fns, fn)
			}
		}
	}
	w.mu.Unlock()
	for _, fn := range fns {
		fn(key, spendingTxid)
	}
}

// remember caches a lookup's answer within the cache's bound.
func (w *Watcher) remember(key string, ans answer) {
	c := cached{ans: ans}
	if !ans.spent || !ans.confirmed {
		c.expires = time.Now().Add(unspentTTL)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.cache[key]; !ok {
		w.cacheKeys = append(w.cacheKeys, key)
		for len(w.cacheKeys) > maxCached {
			delete(w.cache, w.cacheKeys[0])
			w.cacheKeys = w.cacheKeys[1:]
		}
	}
	w.cache[key] = c
}

// normalize parses "txid_vout" or "txid.vout" into the "txid_vout" key.
func normalize(outpoint string) (key, txid string, vout uint32, ok bool) {
	i := strings.LastIndexAny(outpoint, "_.")
	if i < 0 || !isTxid(outpoint[:i]) {
		return "", "", 0, false
	}
	n, err := strconv.ParseUint(outpoint[i+1:], 10, 32)
	if err != nil {
		return "", "", 0, false
	}
	txid = strings.ToLower(outpoint[:i])
	return txid + "_" + strconv.FormatUint(n, 10), txid, uint32(n), true
}
