package ordtrack

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/BSVanon/Anvil/internal/content"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Maintenance pacing.
const (
	maintainEvery = 30 * time.Second
	// addsPerRound and checksPerRound bound one maintenance round's work.
	addsPerRound   = 20
	checksPerRound = 50
	// pendingCheckEvery spaces one chain's mined-status checks.
	pendingCheckEvery = 2 * time.Minute
	addRetryBase      = time.Minute
	addRetryMax       = 30 * time.Minute
)

// want is a tracked origin not yet confirmed.
type want struct {
	nextTry  time.Time
	attempts int
	refused  bool // not a valid origin: not retried until it is tracked anew
}

// SetTracked makes origins, normalized and deduplicated, the tracked set,
// cut to MaxOrigins. An origin leaving the set stops being watched; its
// history is kept for 24 hours, then dropped. An origin joining it is
// confirmed and followed forward by Run.
func (t *Tracker) SetTracked(origins []string) {
	set := make(map[string]bool, len(origins))
	var order []string
	for _, o := range origins {
		n, ok := NormalizeOutpoint(o)
		if !ok || set[n] {
			continue
		}
		if len(order) >= t.cfg.MaxOrigins {
			t.mu.Lock()
			if !t.capped {
				t.capped = true
				t.log.Warn("tracked origins exceed the cap; the rest are not tracked", "cap", t.cfg.MaxOrigins)
			}
			t.mu.Unlock()
			break
		}
		set[n] = true
		order = append(order, n)
	}

	now := t.now()
	t.mu.Lock()
	for _, o := range order {
		ch := t.chains[o]
		switch {
		case ch == nil:
			if t.wanted[o] == nil {
				t.wanted[o] = &want{}
			}
		case !ch.tracked:
			ch.tracked = true
			ch.m.RemovedAt = 0
			t.saveMetaLocked(ch)
			if ch.isOpen() {
				t.tips[ch.tip.Outpoint] = o
				if err := t.watch.Watch(ch.tip.Outpoint, watchOwner); err != nil {
					t.log.Warn("cannot watch a tracked tip", "origin", o, "error", err)
				}
			}
		}
	}
	for o, ch := range t.chains {
		if set[o] || !ch.tracked {
			continue
		}
		ch.tracked = false
		ch.m.RemovedAt = now.Unix()
		t.saveMetaLocked(ch)
		delete(t.tips, ch.tip.Outpoint)
		t.watch.Unwatch(ch.tip.Outpoint, watchOwner)
	}
	for o := range t.wanted {
		if !set[o] {
			delete(t.wanted, o)
		}
	}
	t.mu.Unlock()
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

func (t *Tracker) saveMetaLocked(ch *chain) {
	chg := newChange()
	chg.putMeta(ch.m)
	if err := t.db.apply(chg); err != nil {
		t.log.Warn("save tracked origin failed", "origin", ch.m.Origin, "error", err)
	}
}

// maintain is one round of Run's periodic work.
func (t *Tracker) maintain(ctx context.Context) {
	t.addWanted(ctx)
	t.catchUp(ctx)
	t.checkPending(ctx)
	t.dropRemoved()
}

// addWanted confirms tracked origins that are due a try.
func (t *Tracker) addWanted(ctx context.Context) {
	now := t.now()
	t.mu.Lock()
	var due []string
	for o, w := range t.wanted {
		if !w.refused && !now.Before(w.nextTry) {
			due = append(due, o)
		}
	}
	t.mu.Unlock()
	sort.Strings(due)
	if len(due) > addsPerRound {
		due = due[:addsPerRound]
	}
	for _, o := range due {
		if ctx.Err() != nil {
			return
		}
		err := t.addOrigin(ctx, o)
		t.mu.Lock()
		w := t.wanted[o]
		switch {
		case w == nil:
		case err == nil:
			delete(t.wanted, o)
		case errors.Is(err, errInvalid):
			w.refused = true
			t.log.Warn("tracked origin refused", "origin", o, "error", err)
		default:
			w.attempts++
			backoff := addRetryBase << min(w.attempts, 5)
			w.nextTry = now.Add(min(backoff, addRetryMax))
			t.log.Debug("tracked origin not confirmed yet", "origin", o, "error", err)
		}
		t.mu.Unlock()
		if err == nil {
			t.follow(ctx, o)
		}
	}
}

// addOrigin fetches origin, checks that it is a 1-sat output, plain or
// carrying an inscription envelope, proven mined, and confirms that it is
// an origin by walking back from it, then records it as version 0. An
// origin not yet proven mined is tried again later: links are only ever
// followed from a mined start.
func (t *Tracker) addOrigin(ctx context.Context, origin string) error {
	txid, vout, _ := splitOutpoint(origin)
	r := &reader{v: t.v, fetch: true, held: map[string]*transaction.Transaction{}}
	tx, err := r.tx(ctx, txid)
	if err != nil {
		return err
	}
	if int(vout) >= len(tx.Outputs) || tx.Outputs[vout].Satoshis != 1 {
		return errors.Join(errInvalid, errNotOneSat)
	}
	if tx.MerklePath == nil {
		return fmt.Errorf("%w: %s is not proven mined", errRetryLater, txid)
	}
	if err := t.v.spv(ctx, tx); err != nil {
		return fmt.Errorf("%w: %v", errRetryLater, err)
	}
	if _, err := proveOrigin(ctx, origin, r.tx, 0); err != nil {
		if errors.Is(err, errWalkTooLong) || errors.Is(err, errNotOneSat) {
			return errors.Join(errInvalid, errors.New("a transfer from an earlier 1-sat output, not an origin"))
		}
		return err
	}
	l := link{Outpoint: origin, Txid: txid, Kind: kindOrigin, Status: statusMined, Height: tx.MerklePath.BlockHeight, Seen: t.now().Unix(), Seq: 0}
	if env, ok := content.ParseOrdEnvelope(tx.Outputs[vout].LockingScript.Bytes()); ok {
		l.Inscribed, l.ContentType = true, env.ContentType
	}
	m := meta{Origin: origin, Tip: origin, Links: 1, Versions: 1}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.wanted[origin] == nil || t.chains[origin] != nil {
		return nil // left the tracked set, or added meanwhile
	}
	chg := newChange()
	chg.putLink(origin, 0, l)
	chg.putMeta(m)
	if err := t.db.apply(chg); err != nil {
		return err
	}
	ch := &chain{m: m, latest: l, tracked: true}
	t.chains[origin] = ch
	t.moveTipLocked(origin, ch, l, m)
	return nil
}

// dropRemoved deletes chains that left the tracked set over 24 hours ago.
func (t *Tracker) dropRemoved() {
	cutoff := t.now().Add(-removedRetention).Unix()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneRolledBackLocked()
	for o, ch := range t.chains {
		if ch.tracked || ch.m.RemovedAt == 0 || ch.m.RemovedAt > cutoff {
			continue
		}
		if err := t.db.drop(o); err != nil {
			t.log.Warn("drop untracked origin failed", "origin", o, "error", err)
			continue
		}
		delete(t.chains, o)
	}
}
