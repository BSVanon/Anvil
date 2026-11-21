package api

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// UTXONoncePool wraps a NonceProvider with pre-minting for fast 402 challenge issuance.
// Maintains a pool of ready nonces so challenges don't wait for wallet CreateAction.
//
// Every mint, the refills and an empty pool's on-demand mints alike, spends
// from the process-wide mint budget (payment_budget.go). An empty pool whose
// budget is spent mints nothing and returns a *mintBudgetError.
//
// See Rui da Silva's "Replay Protection Without Databases" and
// STRATEGIC_TOPICS.md Topic 12 / TODO_REMAINING.md.
type UTXONoncePool struct {
	inner    NonceProvider // the minting provider behind the mint budget
	logger   *slog.Logger
	mu       sync.Mutex
	pool     []*NonceUTXO
	poolSize int
	minting  bool
}

// NewUTXONoncePool wraps a NonceProvider with a pre-mint pool.
// poolSize is the target number of ready nonces (default: 100).
func NewUTXONoncePool(inner NonceProvider, poolSize int, logger *slog.Logger) *UTXONoncePool {
	return newUTXONoncePool(inner, poolSize, logger, defaultMintBudget)
}

// newUTXONoncePool is NewUTXONoncePool with the mint budget to spend from.
func newUTXONoncePool(inner NonceProvider, poolSize int, logger *slog.Logger, budget *mintBudget) *UTXONoncePool {
	if poolSize <= 0 {
		poolSize = 100
	}
	if logger == nil {
		logger = slog.Default()
	}
	p := &UTXONoncePool{
		inner:    withMintBudget(inner, budget),
		logger:   logger,
		pool:     make([]*NonceUTXO, 0, poolSize),
		poolSize: poolSize,
	}
	go p.replenish()
	return p
}

// MintNonce returns a ready nonce UTXO from the pool. If the pool is empty it
// mints one on demand, which the mint budget may refuse with a
// *mintBudgetError.
func (p *UTXONoncePool) MintNonce(ctx context.Context) (*NonceUTXO, error) {
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

	nonce, err := p.inner.MintNonce(ctx)
	if err != nil {
		var spent *mintBudgetError
		if errors.As(err, &spent) {
			// Logged at debug: a caller can ask for challenges as fast as the
			// rate limiter lets it, and each refusal would log a line.
			p.logger.Debug("nonce pool empty and the mint budget is spent", "retry_after", spent.retryAfter)
		}
		return nil, err
	}
	p.logger.Warn("nonce pool empty, minted a nonce on demand")

	go p.replenish()
	return nonce, nil
}

// PoolSize returns the current number of ready nonces.
func (p *UTXONoncePool) PoolSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pool)
}

// replenish mints nonces until the pool is full or the mint budget is spent.
// The next nonce issued below a quarter of the pool tries again.
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
		ctx, cancel := context.WithTimeout(context.Background(), nonceMintTimeout)
		nonce, err := p.inner.MintNonce(ctx)
		cancel()
		if err != nil {
			var spent *mintBudgetError
			if errors.As(err, &spent) {
				p.logger.Info("nonce pool refill paused: the mint budget is spent", "minted", minted, "retry_after", spent.retryAfter)
			} else {
				p.logger.Warn("nonce mint failed, stopping replenish", "minted", minted, "error", err)
			}
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
