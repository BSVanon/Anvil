package bond

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestCheckerNotRequired(t *testing.T) {
	c := NewChecker(0, "")
	if c.Required() {
		t.Fatal("checker with minSats=0 should not be required")
	}
	pk, _ := ec.NewPrivateKey()
	bal, err := c.VerifyBond(pk.PubKey())
	if err != nil {
		t.Fatalf("unexpected error when bond not required: %v", err)
	}
	if bal != 0 {
		t.Fatalf("expected 0 balance when not required, got %d", bal)
	}
}

func TestCheckerRequired(t *testing.T) {
	c := NewChecker(10000, "")
	if !c.Required() {
		t.Fatal("checker with minSats=10000 should be required")
	}
	if c.MinSats() != 10000 {
		t.Fatalf("expected MinSats=10000, got %d", c.MinSats())
	}
}

func TestCheckerRejectsUnfundedKey(t *testing.T) {
	// Generate a random key — will have no UTXOs on mainnet
	c := NewChecker(10000, "")
	pk, _ := ec.NewPrivateKey()
	_, err := c.VerifyBond(pk.PubKey())
	if err == nil {
		t.Fatal("expected error for unfunded random key")
	}
}

func TestAddressDerivation(t *testing.T) {
	pk, _ := ec.NewPrivateKey()
	addr, err := pubKeyToAddress(pk.PubKey())
	if err != nil {
		t.Fatalf("address derivation failed: %v", err)
	}
	if len(addr) < 25 || addr[0] != '1' {
		t.Fatalf("invalid P2PKH address: %s", addr)
	}
}

// wocStub returns an httptest server that responds with the given balance.
// hitCount tracks how many requests the server receives.
func wocStub(balance int, hitCount *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"result":[{"tx_hash":"aabb","tx_pos":0,"value":%d,"height":900000}]}`, balance)
	}))
}

// wocStubFailing returns an httptest server that always returns 500.
func wocStubFailing(hitCount *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
}

func TestCacheHitAvoidsSecondRequest(t *testing.T) {
	var hits atomic.Int32
	srv := wocStub(50000, &hits)
	defer srv.Close()

	c := NewChecker(10000, srv.URL)
	pk, _ := ec.NewPrivateKey()

	// First call — hits the server
	bal, err := c.VerifyBond(pk.PubKey())
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if bal != 50000 {
		t.Fatalf("expected 50000, got %d", bal)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 server hit, got %d", hits.Load())
	}

	// Second call — should come from cache, no new server hit
	bal2, err := c.VerifyBond(pk.PubKey())
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if bal2 != 50000 {
		t.Fatalf("expected cached 50000, got %d", bal2)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected still 1 server hit after cache, got %d", hits.Load())
	}
}

func TestFailuresAreNotCached(t *testing.T) {
	var hits atomic.Int32
	srv := wocStubFailing(&hits)
	defer srv.Close()

	c := NewChecker(10000, srv.URL)
	pk, _ := ec.NewPrivateKey()

	// First call — fails
	_, err := c.VerifyBond(pk.PubKey())
	if err == nil {
		t.Fatal("expected error from failing server")
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 hit, got %d", hits.Load())
	}

	// Second call — should NOT be cached, hits server again
	_, err = c.VerifyBond(pk.PubKey())
	if err == nil {
		t.Fatal("expected error from failing server on second call")
	}
	if hits.Load() != 2 {
		t.Fatalf("failures should not be cached; expected 2 hits, got %d", hits.Load())
	}
}

func TestCacheExpiresAfterTTL(t *testing.T) {
	var hits atomic.Int32
	srv := wocStub(50000, &hits)
	defer srv.Close()

	c := NewChecker(10000, srv.URL)
	pk, _ := ec.NewPrivateKey()

	// First call populates cache
	_, err := c.VerifyBond(pk.PubKey())
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Manually expire the cache entry
	c.cacheMu.Lock()
	for k, entry := range c.cache {
		entry.expiresAt = time.Now().Add(-1 * time.Second)
		c.cache[k] = entry
	}
	c.cacheMu.Unlock()

	// Next call should hit server again
	_, err = c.VerifyBond(pk.PubKey())
	if err != nil {
		t.Fatalf("post-expiry call failed: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected 2 hits after cache expiry, got %d", hits.Load())
	}
}

func TestInsufficientBondNotCached(t *testing.T) {
	var hits atomic.Int32
	srv := wocStub(5000, &hits) // below 10000 threshold
	defer srv.Close()

	c := NewChecker(10000, srv.URL)
	pk, _ := ec.NewPrivateKey()

	// First call — insufficient bond returns error
	_, err := c.VerifyBond(pk.PubKey())
	if err == nil {
		t.Fatal("expected insufficient bond error")
	}

	// Second call — insufficient bond is an error, should not be cached
	_, err = c.VerifyBond(pk.PubKey())
	if err == nil {
		t.Fatal("expected insufficient bond error on second call")
	}
	if hits.Load() != 2 {
		t.Fatalf("insufficient bond errors should not be cached; expected 2 hits, got %d", hits.Load())
	}
}
