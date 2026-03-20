package api

import (
	"log/slog"
	"sync"
	"testing"
)

// mockNonceProvider returns predictable nonces for testing.
type mockNonceProvider struct {
	mu      sync.Mutex
	counter int
}

func (m *mockNonceProvider) MintNonce() (*NonceUTXO, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	return &NonceUTXO{
		TxID:     "mock-txid-" + string(rune('a'+m.counter-1)),
		Vout:     0,
		Satoshis: 1,
	}, nil
}

func TestUTXONoncePoolMintFromPool(t *testing.T) {
	mock := &mockNonceProvider{}
	pool := NewUTXONoncePool(mock, 5, nil)

	// Wait for initial replenish
	for pool.PoolSize() < 5 {
		// busy wait — pool replenishes in background goroutine
	}

	// Pool should have 5 nonces
	if pool.PoolSize() != 5 {
		t.Fatalf("expected pool size 5, got %d", pool.PoolSize())
	}

	// Mint from pool — should be instant (no new provider call)
	nonce, err := pool.MintNonce()
	if err != nil {
		t.Fatalf("MintNonce: %v", err)
	}
	if nonce == nil {
		t.Fatal("expected nonce, got nil")
	}

	// Pool should now have 4
	if pool.PoolSize() != 4 {
		t.Fatalf("expected pool size 4 after mint, got %d", pool.PoolSize())
	}
}

func TestUTXONoncePoolOnDemandWhenEmpty(t *testing.T) {
	mock := &mockNonceProvider{}
	pool := &UTXONoncePool{
		inner:    mock,
		logger:   slog.Default(),
		pool:     make([]*NonceUTXO, 0),
		poolSize: 5,
	}

	// Pool is empty — should mint on-demand
	nonce, err := pool.MintNonce()
	if err != nil {
		t.Fatalf("MintNonce on-demand: %v", err)
	}
	if nonce == nil {
		t.Fatal("expected nonce from on-demand mint")
	}
}

func TestUTXONoncePoolReplenishTriggered(t *testing.T) {
	mock := &mockNonceProvider{}
	pool := NewUTXONoncePool(mock, 8, nil)

	// Wait for initial replenish
	for pool.PoolSize() < 8 {
	}

	// Drain to below 25% (below 2)
	for i := 0; i < 7; i++ {
		pool.MintNonce()
	}

	// Should have 1 left, and replenish should be triggered
	if pool.PoolSize() > 1 {
		t.Fatalf("expected pool size <= 1 after draining 7, got %d", pool.PoolSize())
	}

	// Wait for replenish
	for pool.PoolSize() < 5 {
	}

	if pool.PoolSize() < 5 {
		t.Fatalf("expected pool to replenish above 5, got %d", pool.PoolSize())
	}
}
