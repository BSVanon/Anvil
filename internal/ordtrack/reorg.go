package ordtrack

import (
	"context"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

type blockAnchor struct {
	height uint32
	root   string
}

// checkMined reconciles mined chain tips with the node's best headers. A
// request also performs this check before resolving a sequence, so a stale
// block is never deliberately served between maintenance rounds.
func (t *Tracker) checkMined(ctx context.Context) {
	now := t.now()
	t.mu.Lock()
	origins := make([]string, 0, checksPerRound)
	for origin, ch := range t.chains {
		if len(origins) >= checksPerRound {
			break
		}
		if !ch.tracked || now.Before(ch.nextMinedCheck) {
			continue
		}
		ch.nextMinedCheck = now.Add(minedCheckEvery)
		origins = append(origins, origin)
	}
	t.mu.Unlock()
	for _, origin := range origins {
		if ctx.Err() != nil {
			return
		}
		if err := t.reconcileMined(ctx, origin); err != nil {
			t.log.Warn("best-chain reconciliation failed", "origin", origin, "error", err)
		}
	}
}

// reconcileMined validates the origin and the newest mined link. A valid
// descendant proves its chain prefix. If the newest anchor is stale, the
// first stale anchor and its suffix are removed before following the winner.
func (t *Tracker) reconcileMined(ctx context.Context, origin string) error {
	t.mu.Lock()
	ch := t.chains[origin]
	if ch == nil || !ch.tracked {
		t.mu.Unlock()
		return nil
	}
	links, lastMined := ch.m.Links, ch.firstPending()-1
	t.mu.Unlock()

	first, err := t.db.link(origin, 0)
	if err != nil {
		return fmt.Errorf("read origin anchor: %w", err)
	}
	valid, err := t.linkOnBest(ctx, origin, 0, first)
	if err != nil {
		return err
	}
	if !valid {
		return t.removeStaleOrigin(origin, links)
	}
	if lastMined <= 0 {
		return nil
	}
	last, err := t.db.link(origin, lastMined)
	if err != nil {
		return fmt.Errorf("read latest mined anchor: %w", err)
	}
	valid, err = t.linkOnBest(ctx, origin, lastMined, last)
	if err != nil || valid {
		return err
	}

	stale := -1
	for i := 1; i <= lastMined; i++ {
		l, readErr := t.db.link(origin, i)
		if readErr != nil {
			return fmt.Errorf("read mined link %d: %w", i, readErr)
		}
		valid, checkErr := t.linkOnBest(ctx, origin, i, l)
		if checkErr != nil {
			return checkErr
		}
		if !valid {
			stale = i
			break
		}
	}
	if stale < 0 {
		return nil
	}

	t.mu.Lock()
	ch = t.chains[origin]
	if ch == nil || !ch.tracked || ch.m.Links != links {
		t.mu.Unlock()
		return nil
	}
	err = t.rollbackLocked(origin, ch, stale, "a mined block left the best chain")
	t.mu.Unlock()
	if err != nil {
		return err
	}
	t.follow(ctx, origin)
	return nil
}

func (t *Tracker) linkOnBest(ctx context.Context, origin string, index int, l link) (bool, error) {
	missing := l.MerkleRoot == ""
	if !missing {
		root, err := chainhash.NewHashFromHex(l.MerkleRoot)
		if err == nil {
			valid, checkErr := t.cfg.Chain.IsValidRootForHeight(ctx, root, l.Height)
			if checkErr != nil {
				return false, checkErr
			}
			if valid {
				return true, nil
			}
		}
	}
	a, valid, err := t.anchorForTx(ctx, l.Txid)
	if err != nil {
		if missing {
			return false, err
		}
		return false, nil
	}
	if !valid {
		return false, nil
	}
	if err := t.updateAnchor(origin, index, l.Txid, a); err != nil {
		return false, err
	}
	return true, nil
}

func (t *Tracker) anchorForTx(ctx context.Context, txid string) (blockAnchor, bool, error) {
	tx, err := t.cfg.Source.Tx(ctx, txid)
	if err != nil {
		return blockAnchor{}, false, err
	}
	if tx.TxID().String() != txid {
		return blockAnchor{}, false, fmt.Errorf("fetched bytes for %s hash to %s", txid, tx.TxID())
	}
	if tx.MerklePath == nil {
		return blockAnchor{}, false, nil
	}
	root, err := tx.MerklePath.ComputeRoot(tx.TxID())
	if err != nil {
		return blockAnchor{}, false, err
	}
	valid, err := t.cfg.Chain.IsValidRootForHeight(ctx, root, tx.MerklePath.BlockHeight)
	if err != nil || !valid {
		return blockAnchor{}, valid, err
	}
	return blockAnchor{height: tx.MerklePath.BlockHeight, root: root.String()}, true, nil
}

func (t *Tracker) updateAnchor(origin string, index int, txid string, a blockAnchor) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch := t.chains[origin]
	if ch == nil || index >= ch.m.Links {
		return nil
	}
	l, err := t.db.link(origin, index)
	if err != nil || l.Txid != txid {
		return err
	}
	l.Height, l.MerkleRoot = a.height, a.root
	c := newChange()
	c.putLink(origin, index, l)
	if err := t.db.apply(c); err != nil {
		return err
	}
	if index == ch.m.Links-1 {
		ch.tip = l
	}
	if l.Seq == ch.latest.Seq {
		ch.latest = l
	}
	return nil
}

func (t *Tracker) removeStaleOrigin(origin string, links int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch := t.chains[origin]
	if ch == nil || !ch.tracked || ch.m.Links != links {
		return nil
	}
	delete(t.tips, ch.tip.Outpoint)
	t.watch.Unwatch(ch.tip.Outpoint, watchOwner)
	if err := t.db.drop(origin); err != nil {
		return err
	}
	delete(t.chains, origin)
	t.wanted[origin] = &want{}
	t.rollbacks.Add(1)
	t.log.Info("removed a tracked origin whose block left the best chain", "origin", origin)
	return nil
}
