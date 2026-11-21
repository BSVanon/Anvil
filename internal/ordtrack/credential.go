package ordtrack

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Bounds on the BEEFs kept for spends this node was told about, so that
// verifying them reads what came with them instead of fetching.
const (
	beefCacheEntries = 64
	beefCacheBytes   = 8 << 20
	beefCacheEntry   = 1 << 20 // a larger BEEF is not kept
	beefCacheTTL     = 10 * time.Minute
)

var (
	errNotTransfer = errors.New("the spend does not move the token to a new 1-sat output")
	errStaleTip    = errors.New("not the current tip of a tracked origin")
)

// Active reports whether any tracked origin has a tip to follow. It is
// POST /broadcast's first check, before any of the request is read.
func (t *Tracker) Active() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.tips) > 0
}

// SpendsTip returns the tracked origin, and its current tip, that tx's
// first input spending any tracked tip spends. It is one map lookup per
// input.
func (t *Tracker) SpendsTip(tx *transaction.Transaction) (origin, tip string, ok bool) {
	if tx == nil || len(tx.Inputs) > maxInputs {
		return "", "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.tips) == 0 {
		return "", "", false
	}
	for _, in := range tx.Inputs {
		if in.SourceTXID == nil {
			continue
		}
		key := outpointString(in.SourceTXID.String(), in.SourceTxOutIndex)
		if o, hit := t.tips[key]; hit {
			return o, key, true
		}
	}
	return "", "", false
}

// VerifyTipUpdate verifies, from what n holds alone, that n's subject
// spends tip, origin's current tip, as a transfer to a new 1-sat output:
// the checks every reported spend gets (see verify), with nothing
// fetched. accept records the spend as origin's new, unmined tip
// and tells peers; call it only once the transaction is broadcast. Any
// other outcome, an end or a burn included, is an error.
func (t *Tracker) VerifyTipUpdate(ctx context.Context, n *beefnorm.BEEF, origin, tip string) (accept func(), err error) {
	if n == nil || n.Subject == nil || n.Tx == nil {
		return nil, errInvalid
	}
	t.mu.Lock()
	ch := t.chains[origin]
	if ch == nil || !ch.isOpen() || ch.tip.Outpoint != tip {
		t.mu.Unlock()
		return nil, errStaleTip
	}
	trusted := ch.trusted()
	rolledBack := t.wasRolledBackLocked(n.Subject.String())
	t.mu.Unlock()
	if rolledBack {
		return nil, errRolledBack
	}

	c := candidate{origin: origin, tip: tip, txid: n.Subject.String(), beef: n}
	s, err := t.v.verify(ctx, c, trusted, false)
	if err != nil {
		return nil, err
	}
	if s.kind != Transfer {
		return nil, fmt.Errorf("%w: %s", errNotTransfer, s.kind)
	}
	return func() {
		applied, err := t.apply(c, s)
		if err != nil {
			t.log.Debug("tip update not recorded", "origin", origin, "txid", c.txid, "error", err)
		}
		if applied {
			raw, _ := n.Atomic()
			t.publish(origin, tip, outpointString(s.txid, uint32(s.vout)), raw) // #nosec G115 // vout indexes an output
		}
	}, nil
}

// NoteBroadcast keeps the BEEF a transaction this node broadcast came
// with, when the transaction spends a tracked tip, for the verification of
// the spend the spend watch then reports. It does not parse the BEEF.
func (t *Tracker) NoteBroadcast(tx *transaction.Transaction, beef []byte) {
	if len(beef) == 0 || len(beef) > beefCacheEntry {
		return
	}
	if _, _, ok := t.SpendsTip(tx); !ok {
		return
	}
	raw := append([]byte(nil), beef...)
	t.mu.Lock()
	t.beefs.put(tx.TxID().String(), nil, raw, t.now())
	t.mu.Unlock()
}

// parseBEEF is beefnorm.Parse behind a panic recover, as the node's other
// BEEF ingress paths call it.
func parseBEEF(raw []byte) (n *beefnorm.BEEF, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = nil, fmt.Errorf("%w: BEEF parse panicked: %v", errInvalid, r)
		}
	}()
	return beefnorm.Parse(raw)
}

// beefCache holds up to beefCacheEntries BEEFs, beefCacheBytes in all, each
// for beefCacheTTL, keyed by the txid of their subject. The Tracker's mutex
// guards it.
type beefCache struct {
	byTxid map[string]cachedBEEF
	order  []string // oldest first
	bytes  int
}

type cachedBEEF struct {
	n   *beefnorm.BEEF // nil until parsed
	raw []byte
	at  time.Time
}

func newBeefCache() *beefCache { return &beefCache{byTxid: make(map[string]cachedBEEF)} }

func (c *beefCache) put(txid string, n *beefnorm.BEEF, raw []byte, now time.Time) {
	if len(raw) > beefCacheEntry {
		return
	}
	c.remove(txid)
	c.byTxid[txid] = cachedBEEF{n: n, raw: raw, at: now}
	c.order = append(c.order, txid)
	c.bytes += len(raw)
	for len(c.order) > 0 && (len(c.order) > beefCacheEntries || c.bytes > beefCacheBytes) {
		c.remove(c.order[0])
	}
}

// take removes txid's BEEF and returns it, parsed or not, unless it has
// expired.
func (c *beefCache) take(txid string, now time.Time) (*beefnorm.BEEF, []byte) {
	e, ok := c.byTxid[txid]
	if !ok {
		return nil, nil
	}
	c.remove(txid)
	if now.Sub(e.at) > beefCacheTTL {
		return nil, nil
	}
	return e.n, e.raw
}

func (c *beefCache) remove(txid string) {
	e, ok := c.byTxid[txid]
	if !ok {
		return
	}
	delete(c.byTxid, txid)
	c.bytes -= len(e.raw)
	for i, id := range c.order {
		if id == txid {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}
