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
	"github.com/syndtr/goleveldb/leveldb"
)

// watchOwner is the tracker's owner name in the spend watch.
const watchOwner = "ordtrack"

// Defaults and fixed bounds.
const (
	DefaultPendingTimeout  = 24 * time.Hour
	DefaultMaxOrigins      = 1000
	immutableConfirmations = 6
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
	// reserved holds a verified HTTP tip update from authorization until its
	// broadcast either fails or is recorded.
	reserved map[string]string // tip outpoint -> spending txid
	wanted   map[string]*want  // tracked origins not yet confirmed
	beefs    *beefCache
	hinted   map[string]struct{} // txids last reported by a peer's hint
	capped   bool                // the tracked set was cut to MaxOrigins
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
		cfg:      cfg,
		db:       db,
		v:        newVerifier(cfg.Source, cfg.Chain),
		watch:    cfg.Watcher,
		log:      cfg.Logger,
		now:      time.Now,
		chains:   make(map[string]*chain),
		tips:     make(map[string]string),
		reserved: make(map[string]string),
		wanted:   make(map[string]*want),
		beefs:    newBeefCache(),
		hinted:   make(map[string]struct{}),
		behind:   make(map[string]bool),

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
	for _, stored := range metas {
		m, err := t.db.migrateSequence(stored)
		if err != nil {
			return fmt.Errorf("migrate sequence history of %s: %w", stored.Origin, err)
		}
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
	reserved := t.reserved[outpoint]
	_, gossip := t.hinted[spendingTxid]
	delete(t.hinted, spendingTxid)
	t.mu.Unlock()
	// The reserving request records its own candidate after the broadcast.
	// Other candidates are left for the spend watch to report again after
	// the short reservation ends.
	if !ok || reserved != "" {
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

// Latest returns origin's effective content at its current location. An
// origin this node does not track serves as its own latest content.
func (t *Tracker) Latest(origin string) (string, error) {
	_, contentAt, _, err := t.ResolveVersion(origin, -1)
	if errors.Is(err, content.ErrNotTracked) {
		return origin, nil
	}
	return contentAt, err
}

// At returns origin's version seq, 0 being the origin.
func (t *Tracker) At(origin string, seq int) (string, error) {
	outpoint, _, _, err := t.ResolveVersion(origin, seq)
	if errors.Is(err, content.ErrNotTracked) && seq == 0 {
		return origin, nil
	}
	return outpoint, err
}

// ResolveVersion returns the location named by spend sequence seq, the most
// recent inscription at or before that location, and whether the location is
// still unmined. Sequence -1 names the current location.
func (t *Tracker) ResolveVersion(origin string, seq int) (outpoint, contentOutpoint string, pending bool, err error) {
	resolved, err := t.ResolveVersionAt(origin, seq)
	if err != nil {
		return "", "", false, err
	}
	return resolved.Outpoint, resolved.ContentOutpoint, resolved.Pending, nil
}

// ResolveVersionAt resolves relativeSeq from locator. locator may be an
// origin or any recorded location in its chain. The returned Seq is always
// counted from the origin.
func (t *Tracker) ResolveVersionAt(locator string, relativeSeq int) (content.VersionLocation, error) {
	ref, err := t.db.location(locator)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return content.VersionLocation{}, content.ErrNotTracked
		}
		return content.VersionLocation{}, fmt.Errorf("read version locator %s: %w", locator, err)
	}
	if err := t.reconcileMined(context.Background(), ref.Origin); err != nil {
		return content.VersionLocation{}, fmt.Errorf("check best-chain anchors: %w", err)
	}
	t.mu.Lock()
	ch := t.chains[ref.Origin]
	if ch == nil || !ch.tracked {
		t.mu.Unlock()
		return content.VersionLocation{}, content.ErrNotTracked
	}
	latest, versions := ch.latest, ch.m.Versions
	t.mu.Unlock()
	absoluteSeq := relativeSeq
	switch {
	case relativeSeq == -1:
		absoluteSeq = latest.Seq
	case relativeSeq < -1 || relativeSeq > maxLinks || ref.Seq > maxLinks-relativeSeq:
		return content.VersionLocation{}, content.ErrNoVersion
	default:
		absoluteSeq = ref.Seq + relativeSeq
	}
	if absoluteSeq < ref.Seq || absoluteSeq >= versions {
		return content.VersionLocation{}, content.ErrNoVersion
	}
	l := latest
	if absoluteSeq != latest.Seq {
		l, err = t.db.version(ref.Origin, absoluteSeq)
		if err != nil {
			return content.VersionLocation{}, fmt.Errorf("read version %d of %s: %w", absoluteSeq, ref.Origin, err)
		}
	}
	stable := false
	if l.Status == statusMined {
		if best, heightErr := t.cfg.Chain.CurrentHeight(context.Background()); heightErr == nil && best >= l.Height {
			stable = best-l.Height+1 >= immutableConfirmations
		}
	}
	return content.VersionLocation{
		Origin: ref.Origin, Outpoint: l.Outpoint, ContentOutpoint: l.Content,
		Seq: absoluteSeq, Pending: l.Status == statusPending, Immutable: stable,
	}, nil
}

// History returns every version outpoint of a tracked origin, in order.
func (t *Tracker) History(origin string) []string {
	if err := t.reconcileMined(context.Background(), origin); err != nil {
		t.log.Warn("check version history anchors failed", "origin", origin, "error", err)
		return nil
	}
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
