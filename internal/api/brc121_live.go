package api

import (
	"errors"
	"sync"
)

const maxBRC121ClientJournalEntries = 64

var errBRC121ClientJournalFull = errors.New("this client already has 64 unclaimed payments")

// brc121LiveCounts bounds kept payments per client. Keys are one-way hashes
// made before insertion; client addresses are never retained here.
type brc121LiveCounts struct {
	mu     sync.Mutex
	counts map[[32]byte]int
	owners map[string][32]byte
}

func (c *brc121LiveCounts) reserve(owner [32]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = make(map[[32]byte]int)
		c.owners = make(map[string][32]byte)
	}
	if c.counts[owner] >= maxBRC121ClientJournalEntries {
		return errBRC121ClientJournalFull
	}
	c.counts[owner]++
	return nil
}

func (c *brc121LiveCounts) bind(txid string, owner [32]byte) {
	c.mu.Lock()
	c.owners[txid] = owner
	c.mu.Unlock()
}

func (c *brc121LiveCounts) cancel(owner [32]byte) {
	c.mu.Lock()
	c.decrement(owner)
	c.mu.Unlock()
}

func (c *brc121LiveCounts) release(txid string) {
	c.mu.Lock()
	if owner, ok := c.owners[txid]; ok {
		delete(c.owners, txid)
		c.decrement(owner)
	}
	c.mu.Unlock()
}

func (c *brc121LiveCounts) decrement(owner [32]byte) {
	c.counts[owner]--
	if c.counts[owner] <= 0 {
		delete(c.counts, owner)
	}
}

