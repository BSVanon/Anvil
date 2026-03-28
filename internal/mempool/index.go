// Package mempool provides a sharded in-memory transaction index for P2P
// mempool monitoring. Transactions are partitioned by the first byte of their
// txid hash (256 shards), giving fine-grained locking with minimal contention.
//
// The index is ephemeral — confirmed transactions are evicted by TTL.
// Memory footprint: ~44 bytes per entry (32-byte key + 12-byte metadata).
// 100K entries ≈ 4.4 MB. 1M entries ≈ 44 MB.
package mempool

import (
	"sync"
	"sync/atomic"
	"time"
)

// TxMeta holds lightweight metadata about an indexed transaction.
type TxMeta struct {
	FirstSeen time.Time
	Size      uint32 // tx size in bytes (0 if not fetched)
}

// Index is a sharded in-memory txid set. Each shard is independently locked
// so concurrent writes to different prefix bytes never contend.
type Index struct {
	shards [256]shard
	count  atomic.Int64
}

type shard struct {
	mu  sync.RWMutex
	txs map[[32]byte]TxMeta
}

// NewIndex creates an empty mempool index with pre-allocated shards.
func NewIndex() *Index {
	idx := &Index{}
	for i := range idx.shards {
		idx.shards[i].txs = make(map[[32]byte]TxMeta)
	}
	return idx
}

// Add inserts a transaction into the index. Returns false if already present.
func (idx *Index) Add(txid [32]byte, meta TxMeta) bool {
	s := &idx.shards[txid[0]]
	s.mu.Lock()
	if _, exists := s.txs[txid]; exists {
		s.mu.Unlock()
		return false
	}
	s.txs[txid] = meta
	s.mu.Unlock()
	idx.count.Add(1)
	return true
}

// Has checks whether a txid is in the index.
func (idx *Index) Has(txid [32]byte) bool {
	s := &idx.shards[txid[0]]
	s.mu.RLock()
	_, ok := s.txs[txid]
	s.mu.RUnlock()
	return ok
}

// Remove deletes a txid from the index.
func (idx *Index) Remove(txid [32]byte) {
	s := &idx.shards[txid[0]]
	s.mu.Lock()
	if _, exists := s.txs[txid]; exists {
		delete(s.txs, txid)
		s.mu.Unlock()
		idx.count.Add(-1)
		return
	}
	s.mu.Unlock()
}

// Count returns the total number of indexed transactions.
func (idx *Index) Count() int {
	return int(idx.count.Load())
}

// CountByShard returns the count for a specific prefix byte.
func (idx *Index) CountByShard(prefix byte) int {
	s := &idx.shards[prefix]
	s.mu.RLock()
	n := len(s.txs)
	s.mu.RUnlock()
	return n
}

// ExpireBefore removes all entries with FirstSeen before the cutoff.
// Returns the number of entries evicted. Call periodically.
func (idx *Index) ExpireBefore(cutoff time.Time) int {
	evicted := 0
	for i := range idx.shards {
		s := &idx.shards[i]
		s.mu.Lock()
		for txid, meta := range s.txs {
			if meta.FirstSeen.Before(cutoff) {
				delete(s.txs, txid)
				evicted++
			}
		}
		s.mu.Unlock()
	}
	idx.count.Add(-int64(evicted))
	return evicted
}

// Stats returns a summary of the index state.
type Stats struct {
	Total    int   `json:"total"`
	Shards   int   `json:"active_shards"` // shards with at least 1 entry
	Largest  int   `json:"largest_shard"`
}

// GetStats returns index statistics.
func (idx *Index) GetStats() Stats {
	st := Stats{}
	for i := range idx.shards {
		s := &idx.shards[i]
		s.mu.RLock()
		n := len(s.txs)
		s.mu.RUnlock()
		if n > 0 {
			st.Shards++
			st.Total += n
			if n > st.Largest {
				st.Largest = n
			}
		}
	}
	return st
}
