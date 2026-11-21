package ordtrack

import (
	"context"
	"errors"
)

const (
	// maxFollow bounds how many links one follow walks forward in a row. A
	// chain still spent past them is followed on in the next maintenance
	// rounds.
	maxFollow = 100
	// maxRolledBack bounds how many rolled-back txids are remembered.
	maxRolledBack = 10000
)

var errRolledBack = errors.New("rolled back as unmined; not taken again until it is mined")

// follow walks origin's chain forward from its tip with one-shot spend
// checks, for as long as each spend found verifies as a transfer.
func (t *Tracker) follow(ctx context.Context, origin string) {
	for i := 0; ctx.Err() == nil; i++ {
		t.mu.Lock()
		ch := t.chains[origin]
		if ch == nil || !ch.isOpen() {
			t.mu.Unlock()
			return
		}
		if i == maxFollow {
			t.behind[origin] = true
			t.mu.Unlock()
			return
		}
		tip := ch.tip.Outpoint
		t.mu.Unlock()
		spent, by, err := t.watch.Check(ctx, tip)
		if err != nil || !spent {
			return
		}
		if !t.process(ctx, candidate{origin: origin, tip: tip, txid: by}) {
			return
		}
	}
}

// catchUp goes on following up to addsPerRound chains a follow left
// unfinished.
func (t *Tracker) catchUp(ctx context.Context) {
	t.mu.Lock()
	var due []string
	for o := range t.behind {
		if len(due) == addsPerRound {
			break
		}
		due = append(due, o)
		delete(t.behind, o)
	}
	t.mu.Unlock()
	for _, o := range due {
		t.follow(ctx, o)
	}
}

// rememberRolledBackLocked keeps the txids of links just rolled back for
// PendingTimeout, so that following the chain again does not take one of
// them back while it stays unmined.
func (t *Tracker) rememberRolledBackLocked(removed []link) {
	until := t.now().Add(t.cfg.PendingTimeout)
	for _, l := range removed {
		if len(t.rolledBack) >= maxRolledBack {
			t.pruneRolledBackLocked()
			if len(t.rolledBack) >= maxRolledBack {
				return
			}
		}
		t.rolledBack[l.Txid] = until
	}
}

func (t *Tracker) pruneRolledBackLocked() {
	now := t.now()
	for id, until := range t.rolledBack {
		if !now.Before(until) {
			delete(t.rolledBack, id)
		}
	}
}

// wasRolledBackLocked reports whether txid was rolled back recently.
func (t *Tracker) wasRolledBackLocked(txid string) bool {
	until, ok := t.rolledBack[txid]
	return ok && t.now().Before(until)
}
