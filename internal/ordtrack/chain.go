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
	errLinkCap    = errors.New("origin is at its link cap")
	errPendingCap = errors.New("origin is at its cap of unmined links")
)

// chain is one origin's state in memory: its summary, its last link (the
// tip), its last version and its unmined tail. Older links stay in the
// store only.
type chain struct {
	m         meta
	tip       link
	latest    link
	pending   []link // the unmined tail, oldest first
	tracked   bool
	capLogged bool
	nextCheck time.Time // when checkPending may next look at it
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
	ch := t.chains[cand.origin]
	if ch == nil || !ch.isOpen() || ch.tip.Outpoint != cand.tip {
		return false, nil
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

	l := link{Txid: s.txid, Prev: cand.tip, Kind: s.kind.String(), Status: statusPending, Seen: t.now().Unix(), Seq: -1}
	if s.mined {
		l.Status, l.Height = statusMined, s.height
	}
	if s.kind != Burn {
		l.Outpoint = outpointString(s.txid, uint32(s.vout)) // #nosec G115 // vout indexes an output
	}
	if s.kind == Transfer && s.inscribed {
		l.Inscribed, l.ContentType, l.Seq = true, s.contentType, ch.m.Versions
	}

	next := ch.m
	idx := next.Links
	next.Links++
	if l.Seq >= 0 {
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
			p.Status = statusMined
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

// rollbackLocked removes links from index from onward, all of them
// unmined, and makes the link before them the tip again.
func (t *Tracker) rollbackLocked(origin string, ch *chain, from int, reason string) error {
	first := ch.firstPending()
	if from < first || from >= ch.m.Links || from == 0 {
		return fmt.Errorf("rollback of %s from link %d: only unmined links %d..%d can be rolled back", origin, from, first, ch.m.Links-1)
	}
	removed := ch.pending[from-first:]
	var tip link
	if from-1 >= first {
		tip = ch.pending[from-1-first]
	} else {
		var err error
		if tip, err = t.db.link(origin, from-1); err != nil {
			return fmt.Errorf("read link %d of %s: %w", from-1, origin, err)
		}
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
	ch.pending = ch.pending[:from-first]
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
	t.log.Info("rolled back unmined links of a tracked origin", "origin", origin, "links", len(removed), "reason", reason)
	return nil
}

// markMinedLocked records links first..last as mined, the last at height.
func (t *Tracker) markMinedLocked(origin string, ch *chain, last int, height uint32) error {
	first := ch.firstPending()
	if last < first || last >= ch.m.Links {
		return nil
	}
	chg := newChange()
	for i := first; i <= last; i++ {
		l := ch.pending[i-first]
		l.Status = statusMined
		if i == last {
			l.Height = height
		}
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
