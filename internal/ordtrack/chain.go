package ordtrack

import (
	"errors"
	"fmt"
	"time"
)

// Chain bounds.
const (
	// maxLinks caps the links recorded for one origin; past it more are
	// refused, and logged once.
	maxLinks = 10000
	// maxPendingLinks caps a chain's run of unmined links.
	maxPendingLinks = 25
)

var (
	errLinkCap     = errors.New("origin is at its link cap")
	errPendingCap  = errors.New("origin is at its cap of unmined links")
	errTipReserved = errors.New("tracked tip is reserved by another update")
)

// chain is one origin's state in memory: its summary, its last link (the
// tip), its last version and its unmined tail. Older links stay in the
// store only.
type chain struct {
	m              meta
	tip            link
	latest         link
	pending        []link // the unmined tail, oldest first
	tracked        bool
	capLogged      bool
	nextCheck      time.Time // when checkPending may next look at it
	nextMinedCheck time.Time // when best-chain anchors may next be checked
}

// firstPending is the index of pending[0].
func (c *chain) firstPending() int { return c.m.Links - len(c.pending) }

// trusted holds the txids of links whose outputs a candidate may spend as
// recorded: every unmined link, each verified when it was accepted, and the
// tip once it is known to be mined.
func (c *chain) trusted() map[string]bool {
	t := make(map[string]bool, len(c.pending)+1)
	for _, l := range c.pending {
		t[l.Txid] = true
	}
	if c.tip.Status == statusMined {
		t[c.tip.Txid] = true
	}
	return t
}

// isOpen reports whether the chain still has a 1-sat tip to follow.
func (c *chain) isOpen() bool { return c.tracked && !c.m.Closed }

// apply records a verified spend of c.tip as the chain's next link. It
// reports false when the chain moved on, or closed, since the spend was
// verified.
func (t *Tracker) apply(cand candidate, s *spend) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.applyLocked(cand, s, false)
}

// applyLocked records cand while t.mu is held. allowReserved is true only
// for the HTTP request that owns cand.tip's reservation.
func (t *Tracker) applyLocked(cand candidate, s *spend, allowReserved bool) (bool, error) {
	ch := t.chains[cand.origin]
	if ch == nil || !ch.isOpen() || ch.tip.Outpoint != cand.tip {
		return false, nil
	}
	if owner := t.reserved[cand.tip]; owner != "" && (!allowReserved || owner != cand.txid) {
		return false, errTipReserved
	}
	if ch.m.Links >= maxLinks {
		if !ch.capLogged {
			ch.capLogged = true
			t.log.Warn("tracked origin reached its link cap; later links are refused", "origin", cand.origin, "cap", maxLinks)
		}
		return false, errLinkCap
	}
	if !s.mined && len(ch.pending) >= maxPendingLinks {
		return false, errPendingCap
	}
	if !s.mined && t.wasRolledBackLocked(s.txid) {
		return false, errRolledBack
	}

	l := link{
		Txid: s.txid, Prev: cand.tip, Kind: s.kind.String(), Status: statusPending,
		Seen: t.now().Unix(), Seq: -1, Content: ch.latest.Content, ContentSeq: ch.latest.ContentSeq,
	}
	if s.mined {
		l.Status, l.Height, l.MerkleRoot = statusMined, s.height, s.merkleRoot
	}
	if s.kind != Burn {
		l.Outpoint = outpointString(s.txid, uint32(s.vout)) // #nosec G115 // vout indexes an output
		l.Seq = ch.m.Versions
	}
	if s.kind == Transfer && s.inscribed {
		l.Inscribed, l.ContentType = true, s.contentType
		l.Content, l.ContentSeq = l.Outpoint, l.Seq
	}

	next := ch.m
	idx := next.Links
	next.Links++
	if l.Outpoint != "" {
		next.Versions++
	}
	next.Tip = l.Outpoint
	if s.kind != Transfer {
		next.Closed = true
	}
	chg := newChange()
	chg.putLink(cand.origin, idx, l)
	if s.mined {
		// A mined spend proves every link before it mined.
		for i, p := range ch.pending {
			p.Status, p.Height, p.MerkleRoot = statusMined, s.height, s.merkleRoot
			chg.putLink(cand.origin, ch.firstPending()+i, p)
		}
	}
	chg.putMeta(next)
	if err := t.db.apply(chg); err != nil {
		return false, fmt.Errorf("record link: %w", err)
	}

	t.moveTipLocked(cand.origin, ch, l, next)
	if l.Seq >= 0 {
		ch.latest = l
	}
	if s.mined {
		ch.pending = nil
		if ch.latest.Status == statusPending {
			ch.latest.Status = statusMined
		}
	} else {
		ch.pending = append(ch.pending, l)
	}
	return true, nil
}

// moveTipLocked swaps the chain's tip in memory and in the spend watch.
func (t *Tracker) moveTipLocked(origin string, ch *chain, tip link, m meta) {
	if old := ch.tip.Outpoint; old != "" {
		delete(t.tips, old)
		t.watch.Unwatch(old, watchOwner)
	}
	ch.m, ch.tip = m, tip
	if ch.isOpen() {
		t.tips[tip.Outpoint] = origin
		if err := t.watch.Watch(tip.Outpoint, watchOwner); err != nil {
			t.log.Warn("cannot watch a tracked tip", "origin", origin, "error", err)
		}
	}
}

// rollbackLocked removes links from index onward and makes the preceding
// link the tip again. It handles both unmined tails and mined stale forks.
func (t *Tracker) rollbackLocked(origin string, ch *chain, from int, reason string) error {
	first := ch.firstPending()
	if from <= 0 || from >= ch.m.Links {
		return fmt.Errorf("rollback of %s from link %d outside 1..%d", origin, from, ch.m.Links-1)
	}
	removed := make([]link, ch.m.Links-from)
	for i := range removed {
		l, err := t.db.link(origin, from+i)
		if err != nil {
			return fmt.Errorf("read link %d of %s: %w", from+i, origin, err)
		}
		removed[i] = l
	}
	tip, err := t.db.link(origin, from-1)
	if err != nil {
		return fmt.Errorf("read link %d of %s: %w", from-1, origin, err)
	}
	next := ch.m
	next.Links, next.Tip, next.Closed = from, tip.Outpoint, false
	chg := newChange()
	for i, l := range removed {
		chg.deleteLink(origin, from+i, l)
		if l.Seq >= 0 {
			next.Versions--
		}
	}
	chg.putMeta(next)
	if err := t.db.apply(chg); err != nil {
		return fmt.Errorf("roll back %s: %w", origin, err)
	}

	t.rememberRolledBackLocked(removed)
	keepPending := max(0, from-first)
	if keepPending > len(ch.pending) {
		keepPending = len(ch.pending)
	}
	ch.pending = ch.pending[:keepPending]
	ch.tracked = true
	t.moveTipLocked(origin, ch, tip, next)
	if ch.latest.Seq >= next.Versions {
		latest, err := t.db.version(origin, next.Versions-1)
		if err != nil {
			return fmt.Errorf("read version %d of %s: %w", next.Versions-1, origin, err)
		}
		ch.latest = latest
	}
	t.rollbacks.Add(1)
	t.log.Info("rolled back links of a tracked origin", "origin", origin, "links", len(removed), "reason", reason)
	return nil
}

// markMinedLocked records links first..last as mined, anchored by the proven
// descendant at height and root.
func (t *Tracker) markMinedLocked(origin string, ch *chain, last int, height uint32, root string) error {
	first := ch.firstPending()
	if last < first || last >= ch.m.Links {
		return nil
	}
	chg := newChange()
	for i := first; i <= last; i++ {
		l := ch.pending[i-first]
		l.Status, l.Height, l.MerkleRoot = statusMined, height, root
		chg.putLink(origin, i, l)
		if l.Txid == ch.tip.Txid {
			ch.tip = l
		}
		if l.Seq >= 0 && l.Seq == ch.latest.Seq {
			ch.latest = l
		}
	}
	if err := t.db.apply(chg); err != nil {
		return fmt.Errorf("mark links of %s mined: %w", origin, err)
	}
	ch.pending = ch.pending[last-first+1:]
	return nil
}
