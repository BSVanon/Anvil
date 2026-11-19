package api

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a clock a test sets.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// countingProvider mints dev nonces and counts its mints. Unlike
// DevNonceProvider it does not mark its mints cost-free, so the mint budget
// applies to it as it does to WalletNonceProvider.
type countingProvider struct {
	dev   DevNonceProvider
	mints atomic.Int64
}

func (p *countingProvider) MintNonce() (*NonceUTXO, error) {
	p.mints.Add(1)
	return p.dev.MintNonce()
}

// waitPoolMints waits until prov has minted want nonces and the pool has no
// refill running.
func waitPoolMints(t *testing.T, pool *UTXONoncePool, prov *countingProvider, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pool.mu.Lock()
		idle := !pool.minting
		pool.mu.Unlock()
		if idle && prov.mints.Load() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after 5s the pool's provider minted %d nonces (refill idle %v), want %d", prov.mints.Load(), idle, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMintBudget_BurstThenRate(t *testing.T) {
	clock := newFakeClock()
	b := newMintBudget(mintBurst, mintsPerMinute, clock.now)
	for i := 0; i < mintBurst; i++ {
		if ok, _ := b.take(); !ok {
			t.Fatalf("mint %d of the burst refused", i+1)
		}
	}
	if ok, wait := b.take(); ok || wait != 30*time.Second {
		t.Fatalf("mint past the burst: allowed %v, wait %s; want refused for 30s", ok, wait)
	}
	clock.advance(29 * time.Second)
	if ok, wait := b.take(); ok || wait != time.Second {
		t.Fatalf("29s later: allowed %v, wait %s; want refused for 1s", ok, wait)
	}
	clock.advance(time.Second)
	if ok, _ := b.take(); !ok {
		t.Fatal("30s after the burst the next mint was refused")
	}
	clock.advance(time.Hour)
	n := 0
	for ok, _ := b.take(); ok; ok, _ = b.take() {
		n++
	}
	if n != mintBurst {
		t.Fatalf("after an idle hour the bucket held %d mints, want the burst of %d", n, mintBurst)
	}
}

func TestMintBudget_ConcurrentTakesNeverExceedTheBudget(t *testing.T) {
	b := newMintBudget(mintBurst, mintsPerMinute, newFakeClock().now)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := b.take(); ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := allowed.Load(); n != mintBurst {
		t.Fatalf("1000 concurrent takes allowed %d mints, want %d", n, mintBurst)
	}
}

// The pool's start-up fill, its refills and its on-demand mints all spend one
// budget: in any T the provider mints at most the burst plus T at the rate.
func TestNoncePool_RefillAndOnDemandMintsSpendTheBudget(t *testing.T) {
	clock := newFakeClock()
	prov := &countingProvider{}
	pool := newUTXONoncePool(prov, 100, nil, newMintBudget(mintBurst, mintsPerMinute, clock.now))
	waitPoolMints(t, pool, prov, mintBurst)
	for i := 0; i < mintBurst; i++ {
		if _, err := pool.MintNonce(); err != nil {
			t.Fatalf("pooled nonce %d: %v", i+1, err)
		}
	}
	waitPoolMints(t, pool, prov, mintBurst)
	_, err := pool.MintNonce()
	var spent *mintBudgetError
	if !errors.As(err, &spent) || spent.retryAfter != 30*time.Second {
		t.Fatalf("empty pool, spent budget: got %v, want a mint budget error with 30s", err)
	}
	waitPoolMints(t, pool, prov, mintBurst)

	clock.advance(30 * time.Second)
	if _, err := pool.MintNonce(); err != nil {
		t.Fatalf("on-demand mint 30s later: %v", err)
	}
	waitPoolMints(t, pool, prov, mintBurst+1)

	// 330s in all earn 11 mints; the on-demand mint starts a refill that
	// takes what is left.
	clock.advance(300 * time.Second)
	if _, err := pool.MintNonce(); err != nil {
		t.Fatalf("on-demand mint 330s in: %v", err)
	}
	waitPoolMints(t, pool, prov, mintBurst+11)
	if got := pool.PoolSize(); got != 9 {
		t.Fatalf("pool holds %d nonces, want 9 (21 minted, 12 issued)", got)
	}
}

// A burst of concurrent challenges on a node that mints for every challenge
// (a free node pricing a topic, cmd/anvil/main.go) mints the budget and no
// more; the rest are answered 503 with Retry-After.
func TestPaymentGate_ConcurrentChallengesMintOnlyTheBudget(t *testing.T) {
	prov := &countingProvider{}
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 5, PayeeScriptHex: testPayeeScript(t), NonceProvider: prov,
		mintBudget: newMintBudget(mintBurst, mintsPerMinute, newFakeClock().now)})
	const callers = 200
	codes := make(chan [2]string, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := serveGate(pg, http.MethodGet, "/status", "", "")
			codes <- [2]string{http.StatusText(w.Code), w.Header().Get("Retry-After")}
		}()
	}
	wg.Wait()
	close(codes)
	count := map[[2]string]int{}
	for c := range codes {
		count[c]++
	}
	if count[[2]string{"Payment Required", ""}] != mintBurst || count[[2]string{"Service Unavailable", "30"}] != callers-mintBurst {
		t.Fatalf("got %v, want %d challenges and %d 503s with Retry-After 30", count, mintBurst, callers-mintBurst)
	}
	if n := prov.mints.Load(); n != mintBurst {
		t.Fatalf("%d concurrent challenges minted %d nonces, want %d", callers, n, mintBurst)
	}
	pg.mu.Lock()
	pending, reserved := len(pg.pendingChallenges), pg.reservedPending
	pg.mu.Unlock()
	if pending != mintBurst || reserved != 0 {
		t.Fatalf("%d challenges pending, %d places reserved; want %d and 0: a refused mint gives its place back", pending, reserved, mintBurst)
	}
}

// A pool that is empty when its budget is spent answers 503 with
// Retry-After, and nothing is minted.
func TestPaymentGate_EmptyPoolAndSpentBudgetMintNothing(t *testing.T) {
	prov := &countingProvider{}
	pool := newUTXONoncePool(prov, 5, nil, newMintBudget(5, mintsPerMinute, newFakeClock().now))
	waitPoolMints(t, pool, prov, 5)
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 5, PayeeScriptHex: testPayeeScript(t), NonceProvider: pool})
	if pg.nonceProvider != NonceProvider(pool) {
		t.Fatal("the gate must use the pool as it is: the pool budgets its own mints")
	}
	for i := 0; i < 5; i++ {
		gateChallenge(t, pg, "/status")
	}
	waitPoolMints(t, pool, prov, 5)
	w := serveGate(pg, http.MethodGet, "/status", "", "")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("empty pool, spent budget: got %d Retry-After %q, want 503 with 30", w.Code, w.Header().Get("Retry-After"))
	}
	waitPoolMints(t, pool, prov, 5)
}

// NewUTXONoncePool and NewPaymentGate spend one process-wide budget.
func TestMintBudget_IsProcessWide(t *testing.T) {
	saved := defaultMintBudget
	t.Cleanup(func() { defaultMintBudget = saved })
	defaultMintBudget = newMintBudget(3, mintsPerMinute, newFakeClock().now)

	pooled := &countingProvider{}
	pool := NewUTXONoncePool(pooled, 5, nil)
	waitPoolMints(t, pool, pooled, 3)
	direct := &countingProvider{}
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 5, PayeeScriptHex: testPayeeScript(t), NonceProvider: direct})
	if w := serveGate(pg, http.MethodGet, "/status", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a gate's direct mint after the pool spent the budget: got %d, want 503", w.Code)
	}
	if n := direct.mints.Load(); n != 0 {
		t.Fatalf("the gate minted %d nonces past the shared budget", n)
	}
}

// The budget covers wallet nonces, and only DevNonceProvider and pools are
// left as they are.
func TestMintBudget_CoversWalletNonces(t *testing.T) {
	b := newMintBudget(1, 1, time.Now)
	wallet := NewWalletNonceProvider(nil)
	if got, ok := withMintBudget(wallet, b).(*budgetedNonceProvider); !ok || got.inner != NonceProvider(wallet) || got.budget != b {
		t.Fatalf("WalletNonceProvider is not behind the budget: %T", withMintBudget(wallet, b))
	}
	dev := &DevNonceProvider{}
	pool := &UTXONoncePool{}
	budgeted := &budgetedNonceProvider{inner: wallet, budget: b}
	for _, p := range []NonceProvider{dev, pool, budgeted} {
		if withMintBudget(p, b) != p {
			t.Fatalf("%T was wrapped again", p)
		}
	}
	if withMintBudget(nil, b) != nil {
		t.Fatal("a nil provider was wrapped")
	}
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 5, PayeeScriptHex: testPayeeScript(t), NonceProvider: wallet})
	if got, ok := pg.nonceProvider.(*budgetedNonceProvider); !ok || got.budget != defaultMintBudget {
		t.Fatalf("NewPaymentGate left a wallet provider outside the process-wide budget: %T", pg.nonceProvider)
	}
}

// An honest challenge, proof and receipt still pass under the budget, and
// pass again once the budget has earned back a mint.
func TestX402HonestFlowUnderTheBudget(t *testing.T) {
	clock := newFakeClock()
	key := mustKey(t)
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t),
		NonceProvider: &budgetedNonceProvider{inner: &keyNonceProvider{key: key}, budget: newMintBudget(1, mintsPerMinute, clock.now)}})
	pay := func() {
		t.Helper()
		ch := gateChallenge(t, pg, "/status")
		proof := proofForTx(t, ch, nonceSpend(t, ch.NonceUTXO, key, 1, 200, testPayeeScript(t), nil))
		if w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, proof); w.Code != http.StatusOK || w.Header().Get(HeaderX402Receipt) == "" {
			t.Fatalf("honest proof: got %d %s, want 200 with a receipt", w.Code, w.Body.String())
		}
	}
	pay()
	if w := serveGate(pg, http.MethodGet, "/status", "", ""); w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("challenge past the budget: got %d Retry-After %q, want 503 with 30", w.Code, w.Header().Get("Retry-After"))
	}
	clock.advance(30 * time.Second)
	pay()
}
