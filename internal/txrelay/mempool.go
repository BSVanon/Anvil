package txrelay

import (
	"fmt"
	"sync"
)

// Mempool is a simple in-memory transaction pool keyed by txid.
type Mempool struct {
	mu  sync.RWMutex
	txs map[string][]byte // txid hex → raw transaction bytes
}

// NewMempool creates a new empty mempool.
func NewMempool() *Mempool {
	return &Mempool{txs: make(map[string][]byte)}
}

// Add stores a transaction. Returns an error if already present.
func (m *Mempool) Add(txid string, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.txs[txid]; exists {
		return fmt.Errorf("tx %s already in mempool", txid)
	}
	m.txs[txid] = raw
	return nil
}

// Get retrieves a transaction by txid.
func (m *Mempool) Get(txid string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	raw, ok := m.txs[txid]
	return raw, ok
}

// Has returns whether a transaction is in the mempool.
func (m *Mempool) Has(txid string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.txs[txid]
	return ok
}

// Remove deletes a transaction (e.g. after it's mined).
func (m *Mempool) Remove(txid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.txs, txid)
}

// Count returns the number of transactions in the mempool.
func (m *Mempool) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txs)
}
