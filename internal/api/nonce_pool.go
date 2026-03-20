package api

import (
	"log/slog"
	"sync"
)

// UTXONoncePool wraps a NonceProvider with pre-minting for fast 402 challenge issuance.
// Maintains a pool of ready nonces so challenges don't wait for wallet CreateAction.
//
// See Rui da Silva's "Replay Protection Without Databases" and
// STRATEGIC_TOPICS.md Topic 12 / TODO_REMAINING.md.
type UTXONoncePool struct {
	inner    NonceProvider
	logger   *slog.Logger
	mu       sync.Mutex
	pool     []*NonceUTXO
	poolSize int
	minting  bool
}

// NewUTXONoncePool wraps a NonceProvider with a pre-mint pool.
// poolSize is the target number of ready nonces (default: 100).
func NewUTXONoncePool(inner NonceProvider, poolSize int, logger *slog.Logger) *UTXONoncePool {
	if poolSize <= 0 {
		poolSize = 100
	}
	if logger == nil {
		logger = slog.Default()
	}
	p := &UTXONoncePool{
		inner:    inner,
		logger:   logger,
		pool:     make([]*NonceUTXO, 0, poolSize),
		poolSize: poolSize,
	}
	go p.replenish()
	return p
}

// MintNonce returns a ready nonce UTXO from the pool.
// If pool is empty, mints one on-demand (slower but never fails silently).
func (p *UTXONoncePool) MintNonce() (*NonceUTXO, error) {
	p.mu.Lock()
	if len(p.pool) > 0 {
		nonce := p.pool[len(p.pool)-1]
		p.pool = p.pool[:len(p.pool)-1]
		remaining := len(p.pool)
		p.mu.Unlock()

		if remaining < p.poolSize/4 {
			go p.replenish()
		}

		p.logger.Debug("nonce issued from pool", "remaining", remaining)
		return nonce, nil
	}
	p.mu.Unlock()

	p.logger.Warn("nonce pool empty, minting on-demand")
	nonce, err := p.inner.MintNonce()
	if err != nil {
		return nil, err
	}

	go p.replenish()
	return nonce, nil
}

// PoolSize returns the current number of ready nonces.
func (p *UTXONoncePool) PoolSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pool)
}

// replenish mints nonces until the pool is full.
func (p *UTXONoncePool) replenish() {
	p.mu.Lock()
	if p.minting {
		p.mu.Unlock()
		return
	}
	p.minting = true
	needed := p.poolSize - len(p.pool)
	p.mu.Unlock()

	if needed <= 0 {
		p.mu.Lock()
		p.minting = false
		p.mu.Unlock()
		return
	}

	p.logger.Info("replenishing nonce pool", "needed", needed)
	minted := 0
	for i := 0; i < needed; i++ {
		nonce, err := p.inner.MintNonce()
		if err != nil {
			p.logger.Warn("nonce mint failed, stopping replenish", "minted", minted, "error", err)
			break
		}
		p.mu.Lock()
		p.pool = append(p.pool, nonce)
		p.mu.Unlock()
		minted++
	}

	p.mu.Lock()
	p.minting = false
	p.mu.Unlock()

	if minted > 0 {
		p.logger.Info("nonce pool replenished", "minted", minted, "total", p.PoolSize())
	}
}
