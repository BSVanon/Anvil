package ordtrack

import (
	"context"
	"time"
)

// pendingJob is one chain's unmined tail, as checkPending saw it.
type pendingJob struct {
	origin        string
	oldest        link
	newest        link
	first, newIdx int
}

// checkPending checks the unmined links of up to checksPerRound chains,
// each at most every pendingCheckEvery, through the node's tx-status path.
// It never scans blocks.
func (t *Tracker) checkPending(ctx context.Context) {
	now := t.now()
	var jobs []pendingJob
	t.mu.Lock()
	for o, ch := range t.chains {
		if len(jobs) >= checksPerRound {
			break
		}
		if !ch.tracked || len(ch.pending) == 0 || now.Before(ch.nextCheck) {
			continue
		}
		ch.nextCheck = now.Add(pendingCheckEvery)
		jobs = append(jobs, pendingJob{
			origin: o, oldest: ch.pending[0], newest: ch.pending[len(ch.pending)-1],
			first: ch.firstPending(), newIdx: ch.m.Links - 1,
		})
	}
	t.mu.Unlock()
	for _, j := range jobs {
		if ctx.Err() != nil {
			return
		}
		t.checkChain(ctx, j, now)
	}
}

// checkChain settles one chain's unmined tail. A mined link marks it and
// every link before it mined. The oldest unmined link is rolled back, with
// every link after it, once it has stayed unmined past PendingTimeout, or
// once a different spend of the outpoint it spent is mined; the chain is
// then followed again from the last mined link.
func (t *Tracker) checkChain(ctx context.Context, j pendingJob, now time.Time) {
	if st, err := t.cfg.Source.Status(ctx, j.newest.Txid); err == nil && st.Mined {
		if a, valid, anchorErr := t.anchorForTx(ctx, j.newest.Txid); anchorErr == nil && valid {
			t.settle(j.origin, j.newIdx, j.newest.Txid, func(ch *chain) error {
				return t.markMinedLocked(j.origin, ch, j.newIdx, a.height, a.root)
			})
			return
		}
	}
	if j.first != j.newIdx {
		if st, err := t.cfg.Source.Status(ctx, j.oldest.Txid); err == nil && st.Mined {
			if a, valid, anchorErr := t.anchorForTx(ctx, j.oldest.Txid); anchorErr == nil && valid {
				t.settle(j.origin, j.first, j.oldest.Txid, func(ch *chain) error {
					return t.markMinedLocked(j.origin, ch, j.first, a.height, a.root)
				})
				return
			}
		}
	}

	reason := ""
	if now.Sub(time.Unix(j.oldest.Seen, 0)) >= t.cfg.PendingTimeout {
		reason = "not mined within the pending timeout"
	} else if spent, by, err := t.watch.Check(ctx, j.oldest.Prev); err == nil && spent && by != j.oldest.Txid {
		if t.verifiedMinedSpend(ctx, j.origin, j.oldest.Prev, by) {
			reason = "a conflicting spend was mined"
		}
	}
	if reason == "" {
		return
	}
	if t.settle(j.origin, j.first, j.oldest.Txid, func(ch *chain) error {
		return t.rollbackLocked(j.origin, ch, j.first, reason)
	}) {
		t.follow(ctx, j.origin)
	}
}

// verifiedMinedSpend treats a spent-output response only as a hint. The
// named transaction must pass the same bounded verification as an ordinary
// candidate, including an anchored proof and an input spending tip.
func (t *Tracker) verifiedMinedSpend(ctx context.Context, origin, tip, txid string) bool {
	t.mu.Lock()
	ch := t.chains[origin]
	if ch == nil || !ch.tracked {
		t.mu.Unlock()
		return false
	}
	trusted := ch.trusted()
	t.mu.Unlock()
	s, err := t.v.verify(ctx, candidate{origin: origin, tip: tip, txid: txid}, trusted, true)
	return err == nil && s.mined
}

// settle runs fn on origin's chain if link idx is still the unmined link
// txid, and reports whether fn ran without error.
func (t *Tracker) settle(origin string, idx int, txid string, fn func(*chain) error) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch := t.chains[origin]
	if ch == nil {
		return false
	}
	first := ch.firstPending()
	if idx < first || idx >= ch.m.Links || ch.pending[idx-first].Txid != txid {
		return false
	}
	if err := fn(ch); err != nil {
		t.log.Warn("settling unmined links failed", "origin", origin, "error", err)
		return false
	}
	return true
}
