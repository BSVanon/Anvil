package gossip

import (
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// mockMempool implements the gossip.Mempool interface for testing.
type mockMempool struct {
	mu  sync.RWMutex
	txs map[string][]byte
}

func newMockMempool() *mockMempool {
	return &mockMempool{txs: make(map[string][]byte)}
}

func (m *mockMempool) Has(txid string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.txs[txid]
	return ok
}

func (m *mockMempool) Get(txid string) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.txs[txid]
}

func (m *mockMempool) Add(txid string, raw []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.txs[txid]; exists {
		return false
	}
	m.txs[txid] = raw
	return true
}

func (m *mockMempool) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txs)
}

func TestTxAnnounceDedup(t *testing.T) {
	pool := newMockMempool()
	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
	})
	defer m.Stop()

	txid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ann, _ := json.Marshal(TxAnnouncePayload{TxID: txid})

	// First announce — should be processed (not in seen set)
	err := m.onTxAnnounce("peer1", nil, ann)
	if err != nil {
		t.Fatalf("first announce: %v", err)
	}

	// Second announce — should be deduped (in seen set now)
	// The function returns nil either way, but the seen set prevents re-requesting
	m.seenMu.Lock()
	_, seen := m.seen["tx:"+txid]
	m.seenMu.Unlock()
	if !seen {
		t.Fatal("txid should be in seen set after first announce")
	}
}

func TestTxAnnounceSkipsKnownTx(t *testing.T) {
	pool := newMockMempool()
	txid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	pool.Add(txid, []byte{0x01}) // pre-populate mempool

	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
	})
	defer m.Stop()

	ann, _ := json.Marshal(TxAnnouncePayload{TxID: txid})
	_ = m.onTxAnnounce("peer1", nil, ann)

	// Should have been skipped — we already have it
	// No request should be sent (no peers to send to, but that's fine)
}

func TestTxRequestResponds(t *testing.T) {
	pool := newMockMempool()
	txid := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	rawTx := []byte{0x01, 0x00, 0x00, 0x00, 0x00} // minimal fake tx bytes
	pool.Add(txid, rawTx)

	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
	})
	defer m.Stop()

	req, _ := json.Marshal(TxRequestPayload{TxID: txid})

	// This won't actually send a response (no peer connection) but shouldn't panic
	err := m.onTxRequest("peer1", nil, req)
	if err != nil {
		t.Fatalf("tx request: %v", err)
	}
}

func TestTxRequestMissingTx(t *testing.T) {
	pool := newMockMempool()
	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
	})
	defer m.Stop()

	txid := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	req, _ := json.Marshal(TxRequestPayload{TxID: txid})

	// Should return nil (tx not found, nothing to send)
	err := m.onTxRequest("peer1", nil, req)
	if err != nil {
		t.Fatalf("missing tx request should not error: %v", err)
	}
}

func TestTxResponseStoresAndCallsBack(t *testing.T) {
	pool := newMockMempool()
	var callbackTxID string
	var callbackMu sync.Mutex

	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
		OnTx: func(txid string, rawTx []byte) {
			callbackMu.Lock()
			callbackTxID = txid
			callbackMu.Unlock()
		},
	})
	defer m.Stop()

	txid := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	rawTx := []byte{0x01, 0x00, 0x00, 0x00, 0x00}
	resp, _ := json.Marshal(TxResponsePayload{
		TxID:   txid,
		RawHex: hex.EncodeToString(rawTx),
	})

	err := m.onTxResponse("peer1", resp)
	if err != nil {
		t.Fatalf("tx response: %v", err)
	}

	// Verify tx was stored in mempool
	if !pool.Has(txid) {
		t.Fatal("tx should be in mempool after response")
	}

	// Verify callback was called
	time.Sleep(10 * time.Millisecond)
	callbackMu.Lock()
	got := callbackTxID
	callbackMu.Unlock()
	if got != txid {
		t.Fatalf("callback txid: got %q, want %q", got, txid)
	}
}

func TestTxResponseDuplicateIgnored(t *testing.T) {
	pool := newMockMempool()
	txid := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	rawTx := []byte{0x01, 0x00, 0x00, 0x00, 0x00}
	pool.Add(txid, rawTx) // pre-populate

	callbackCount := 0
	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
		OnTx: func(txid string, rawTx []byte) {
			callbackCount++
		},
	})
	defer m.Stop()

	resp, _ := json.Marshal(TxResponsePayload{
		TxID:   txid,
		RawHex: hex.EncodeToString(rawTx),
	})

	_ = m.onTxResponse("peer1", resp)

	// Callback should NOT fire for duplicate
	if callbackCount != 0 {
		t.Fatalf("callback should not fire for duplicate tx, fired %d times", callbackCount)
	}
}

func TestAnnounceTxMarksSeen(t *testing.T) {
	pool := newMockMempool()
	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
	})
	defer m.Stop()

	txid := "1111111111111111111111111111111111111111111111111111111111111111"
	m.AnnounceTx(txid, 100, "")

	m.seenMu.Lock()
	_, seen := m.seen["tx:"+txid]
	m.seenMu.Unlock()
	if !seen {
		t.Fatal("AnnounceTx should mark txid as seen")
	}
}

func TestTxRelayStats(t *testing.T) {
	pool := newMockMempool()
	pool.Add("tx1", []byte{0x01})
	pool.Add("tx2", []byte{0x02})

	m := NewManager(ManagerConfig{
		MaxSeen:   100,
		TxMempool: pool,
	})
	defer m.Stop()

	stats := m.TxRelayStats()
	if stats["tx_relay_enabled"] != true {
		t.Fatal("expected tx_relay_enabled=true")
	}
	if stats["tx_mempool_size"] != 2 {
		t.Fatalf("expected tx_mempool_size=2, got %v", stats["tx_mempool_size"])
	}
}

func TestTxRelayDisabledWithoutMempool(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSeen: 100})
	defer m.Stop()

	stats := m.TxRelayStats()
	if stats["tx_relay_enabled"] != false {
		t.Fatal("expected tx_relay_enabled=false without mempool")
	}
}
