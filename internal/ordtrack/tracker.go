package ordtrack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BSVanon/Anvil/internal/content"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/spendwatch"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

// watchOwner is the tracker's owner name in the spend watch.
const watchOwner = "ordtrack"

// Defaults and fixed bounds.
const (
	DefaultPendingTimeout = 24 * time.Hour
	DefaultMaxOrigins     = 1000
	// removedRetention is how long a chain that left the tracked set keeps
	// its history before it is dropped.
	removedRetention = 24 * time.Hour
	queueSize        = 256
)

// Config configures a Tracker.
type Config struct {
	// Path is the version store's LevelDB directory.
	Path    string
	Source  Source
	Chain   chaintracker.ChainTracker
	Watcher *spendwatch.Watcher
	// PendingTimeout is how long an unmined link may stay unmined before
	// it is rolled back.
	PendingTimeout time.Duration
	MaxOrigins     int
	// Publish sends a signed envelope to the mesh; nil publishes nothing.
	Publish    func(*envelope.Envelope)
	SigningKey *ec.PrivateKey
	// MaxGossipPayload caps a published envelope's payload.
	MaxGossipPayload int
	Logger           *slog.Logger
}

// Tracker follows tracked origins' chains and serves their versions. Its
// methods are safe for concurrent use; Run does the network work.
type Tracker struct {
	cfg   Config
	db    *store
	v     *verifier
	watch *spendwatch.Watcher
	log   *slog.Logger
	now   func() time.Time

	mu     sync.Mutex
	chains map[string]*chain
	tips   map[string]string // an open chain's tip outpoint -> its origin
	wanted map[string]*want  // tracked origins not yet confirmed
	beefs  *beefCache
	hinted map[string]struct{} // txids last reported by a peer's hint
	capped bool                // the tracked set was cut to MaxOrigins
	// behind holds chains a follow left unfinished; rolledBack the txids
	// of links rolled back, each until when it is not taken again unmined.
	behind     map[string]bool
	rolledBack map[string]time.Time

	queue chan candidate
	kick  chan struct{}
	hints *hintLimiter

	rollbacks, gossipApplied, gossipRejected, dropped atomic.Int64
}

// New opens the version store at cfg.Path and loads every chain in it.
// Chains not removed from the tracked set before the last shutdown start
// out tracked; SetTracked reconciles them.
func New(cfg Config) (*Tracker, error) {
	if cfg.Source == nil || cfg.Chain == nil || cfg.Watcher == nil {
		return nil, errors.New("ordtrack: Source, Chain and Watcher are required")
	}
	if cfg.PendingTimeout <= 0 {
		cfg.PendingTimeout = DefaultPendingTimeout
	}
	if cfg.MaxOrigins <= 0 {
		cfg.MaxOrigins = DefaultMaxOrigins
	}
	if cfg.MaxGossipPayload <= 0 {
		cfg.MaxGossipPayload = defaultGossipPayload
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	db, err := openStore(cfg.Path)
	if err != nil {
		return nil, err
	}
	t := &Tracker{
		cfg:    cfg,
		db:     db,
		v:      newVerifier(cfg.Source, cfg.Chain),
		watch:  cfg.Watcher,
		log:    cfg.Logger,
		now:    time.Now,
		chains: make(map[string]*chain),
		tips:   make(map[string]string),
		wanted: make(map[string]*want),
		beefs:  newBeefCache(),
		hinted: make(map[string]struct{}),
		behind: make(map[string]bool),

		rolledBack: make(map[string]time.Time),
		queue:      make(chan candidate, queueSize),
		kick:       make(chan struct{}, 1),
		hints:      newHintLimiter(),
	}
	if err := t.load(); err != nil {
		_ = db.close()
		return nil, err
	}
	t.watch.OnSpent(watchOwner, t.onSpent)
	return t, nil
}

// load reads every chain back from the store.
func (t *Tracker) load() error {
	metas, err := t.db.metas()
	if err != nil {
		return err
	}
	for _, m := range metas {
		ch := &chain{m: m, tracked: m.RemovedAt == 0}
		if ch.tip, err = t.db.link(m.Origin, m.Links-1); err != nil {
			return fmt.Errorf("load tip of %s: %w", m.Origin, err)
		}
		if ch.latest, err = t.db.version(m.Origin, m.Versions-1); err != nil {
			return fmt.Errorf("load latest version of %s: %w", m.Origin, err)
		}
		for i := m.Links - 1; i > 0 && len(ch.pending) <= maxPendingLinks; i-- {
			l, err := t.db.link(m.Origin, i)
			if err != nil {
				return fmt.Errorf("load link %d of %s: %w", i, m.Origin, err)
			}
			if l.Status != statusPending {
				break
			}
			ch.pending = append([]link{l}, ch.pending...)
		}
		t.chains[m.Origin] = ch
		if ch.isOpen() {
			t.tips[ch.tip.Outpoint] = m.Origin
			if err := t.watch.Watch(ch.tip.Outpoint, watchOwner); err != nil {
				t.log.Warn("cannot watch a tracked tip", "origin", m.Origin, "error", err)
			}
		}
	}
	return nil
}

// Close closes the version store. Call it after Run has returned.
func (t *Tracker) Close() error { return t.db.close() }

// Run does the tracker's network work until ctx is done, one job at a
// time: verifying reported spends, confirming newly tracked origins and
// following them forward, and checking unmined links.
func (t *Tracker) Run(ctx context.Context) {
	tick := time.NewTicker(maintainEvery)
	defer tick.Stop()
	t.maintain(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-t.queue:
			if t.process(ctx, c) {
				t.follow(ctx, c.origin)
			}
		case <-t.kick:
			t.maintain(ctx)
		case <-tick.C:
			t.maintain(ctx)
		}
	}
}

// onSpent is the spend watch's callback: queue the candidate when it spends
// an open chain's tip. It never blocks.
func (t *Tracker) onSpent(outpoint, spendingTxid string) {
	t.mu.Lock()
	origin, ok := t.tips[outpoint]
	_, gossip := t.hinted[spendingTxid]
	delete(t.hinted, spendingTxid)
	t.mu.Unlock()
	if !ok {
		return
	}
	select {
	case t.queue <- candidate{origin: origin, tip: outpoint, txid: spendingTxid, gossip: gossip}:
	default:
		t.dropped.Add(1)
	}
}

// process verifies a candidate and records it. It reports whether the tip
// moved to a new 1-sat output.
func (t *Tracker) process(ctx context.Context, c candidate) bool {
	t.mu.Lock()
	ch := t.chains[c.origin]
	if ch == nil || !ch.isOpen() || ch.tip.Outpoint != c.tip {
		t.mu.Unlock()
		return false
	}
	trusted := ch.trusted()
	var raw []byte
	if c.beef == nil {
		c.beef, raw = t.beefs.take(c.txid, t.now())
	}
	t.mu.Unlock()
	if c.beef == nil && raw != nil {
		if n, err := parseBEEF(raw); err == nil && n.Subject.String() == c.txid {
			c.beef = n
		}
	}

	s, err := t.v.verify(ctx, c, trusted, true)
	if err == nil {
		var applied bool
		if applied, err = t.apply(c, s); applied {
			if c.gossip {
				t.gossipApplied.Add(1)
			} else if s.kind == Transfer {
				var beef []byte
				if c.beef != nil {
					beef, _ = c.beef.Atomic()
				}
				t.publish(c.origin, c.tip, outpointString(s.txid, uint32(s.vout)), beef) // #nosec G115 // vout indexes an output
			}
			return s.kind == Transfer
		}
	}
	if err != nil {
		if c.gossip {
			t.gossipRejected.Add(1)
		}
		t.log.Debug("candidate spend not recorded", "origin", c.origin, "txid", c.txid, "error", err)
	}
	return false
}

// Latest returns origin's latest version. An origin this node does not
// track serves as its own latest version.
func (t *Tracker) Latest(origin string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ch := t.chains[origin]; ch != nil && ch.tracked {
		return ch.latest.Outpoint, nil
	}
	return origin, nil
}

// At returns origin's version seq, 0 being the origin.
func (t *Tracker) At(origin string, seq int) (string, error) {
	outpoint, _, err := t.ResolveVersion(origin, seq)
	if errors.Is(err, content.ErrNotTracked) && seq == 0 {
		return origin, nil
	}
	return outpoint, err
}

// ResolveVersion returns origin's version seq, -1 being the latest, and
// whether that version is still unmined.
func (t *Tracker) ResolveVersion(origin string, seq int) (outpoint string, pending bool, err error) {
	t.mu.Lock()
	ch := t.chains[origin]
	if ch == nil || !ch.tracked {
		t.mu.Unlock()
		return "", false, content.ErrNotTracked
	}
	latest, versions := ch.latest, ch.m.Versions
	t.mu.Unlock()
	switch {
	case seq == -1:
		return latest.Outpoint, latest.Status == statusPending, nil
	case seq < -1 || seq >= versions:
		return "", false, content.ErrNoVersion
	case seq == latest.Seq:
		return latest.Outpoint, latest.Status == statusPending, nil
	}
	l, err := t.db.version(origin, seq)
	if err != nil {
		return "", false, fmt.Errorf("read version %d of %s: %w", seq, origin, err)
	}
	return l.Outpoint, l.Status == statusPending, nil
}

// History returns every version outpoint of a tracked origin, in order.
func (t *Tracker) History(origin string) []string {
	t.mu.Lock()
	ch := t.chains[origin]
	tracked := ch != nil && ch.tracked
	t.mu.Unlock()
	if !tracked {
		return nil
	}
	out, err := t.db.versionOutpoints(origin, maxLinks)
	if err != nil {
		t.log.Warn("read version history failed", "origin", origin, "error", err)
	}
	return out
}

// Stats returns the tracker's and its spend watch's counters.
func (t *Tracker) Stats() map[string]int64 {
	t.mu.Lock()
	var origins, pending int64
	for _, ch := range t.chains {
		if ch.tracked {
			origins++
			pending += int64(len(ch.pending))
		}
	}
	t.mu.Unlock()
	polls, pollErrors := t.watch.Stats()
	return map[string]int64{
		"ordtrack_origins":       origins,
		"ordtrack_pending":       pending,
		"ordtrack_rollbacks":     t.rollbacks.Load(),
		"spendwatch_polls":       polls,
		"spendwatch_poll_errors": pollErrors,
		"ordtip_gossip_applied":  t.gossipApplied.Load(),
		"ordtip_gossip_rejected": t.gossipRejected.Load(),
	}
}
