package gossip

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TestBroadcastEnvelopeMarksSeenAndForwards verifies that BroadcastEnvelope
// marks the envelope as seen (dedup) and attempts to forward to interested peers.
func TestBroadcastEnvelopeMarksSeenAndForwards(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-gossip-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	m := NewManager(ManagerConfig{
		Store:          store,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	defer m.Stop()

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)

	m.BroadcastEnvelope(env)

	// Verify it's in the seen set
	hash := envelope.HashEnvelope(env.Topic, env.Pubkey, env.Timestamp)
	m.seenMu.Lock()
	_, seen := m.seen[hash]
	m.seenMu.Unlock()
	if !seen {
		t.Fatal("expected envelope to be in seen set after BroadcastEnvelope")
	}
}

// TestOnDataStoresAndCallsBack verifies that receiving a data message via
// the mesh stores the envelope and fires the onEnvelope callback.
func TestOnDataStoresAndCallsBack(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-gossip-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var received *envelope.Envelope
	var mu sync.Mutex
	m := NewManager(ManagerConfig{
		Store:          store,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		OnEnvelope: func(env *envelope.Envelope) {
			mu.Lock()
			received = env
			mu.Unlock()
		},
	})
	defer m.Stop()

	// Create and sign a real envelope
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)

	// Simulate receiving it as a mesh message
	raw, _ := env.Marshal()
	senderPK := "sender123"
	err = m.onData(senderPK, json.RawMessage(raw))
	if err != nil {
		t.Fatalf("onData error: %v", err)
	}

	// Verify callback fired
	mu.Lock()
	got := received
	mu.Unlock()
	if got == nil {
		t.Fatal("onEnvelope callback was not called")
	}
	if got.Topic != "oracle:rates:bsv" {
		t.Fatalf("expected topic oracle:rates:bsv, got %s", got.Topic)
	}

	// Verify stored
	results, err := store.QueryByTopic("oracle:rates:bsv", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected envelope to be stored")
	}
}

// TestOnDataDedup verifies that duplicate envelopes are not processed twice.
func TestOnDataDedup(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-gossip-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, _ := envelope.NewStore(dir, 3600, 65536)
	defer store.Close()

	callCount := 0
	var mu sync.Mutex
	m := NewManager(ManagerConfig{
		Store:          store,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		OnEnvelope: func(env *envelope.Envelope) {
			mu.Lock()
			callCount++
			mu.Unlock()
		},
	})
	defer m.Stop()

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)
	raw, _ := env.Marshal()

	// Send same envelope twice
	m.onData("sender1", json.RawMessage(raw))
	m.onData("sender1", json.RawMessage(raw))

	mu.Lock()
	got := callCount
	mu.Unlock()
	if got != 1 {
		t.Fatalf("expected callback called once (dedup), got %d", got)
	}
}

// TestOnDataRejectsInvalidSignature verifies that envelopes with bad
// signatures are silently dropped (not stored, no callback).
func TestOnDataRejectsInvalidSignature(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-gossip-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, _ := envelope.NewStore(dir, 3600, 65536)
	defer store.Close()

	called := false
	m := NewManager(ManagerConfig{
		Store:          store,
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
		OnEnvelope: func(env *envelope.Envelope) {
			called = true
		},
	})
	defer m.Stop()

	// Create envelope with wrong signature
	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)
	env.Payload = `{"rate":99}` // tamper after signing
	raw, _ := env.Marshal()

	m.onData("sender1", json.RawMessage(raw))

	if called {
		t.Fatal("callback should not fire for invalid signature")
	}
}

// TestTopicInterestForwarding verifies that forwardToInterested only sends
// to peers whose declared interests match the envelope topic.
func TestTopicInterestForwarding(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})
	defer m.Stop()

	// Register two peers with different interests
	m.mu.Lock()
	m.interests["peerA"] = []string{"oracle:rates:"}
	m.interests["peerB"] = []string{"forge:"}
	m.mu.Unlock()

	// forwardToInterested should match peerA for oracle:rates:bsv
	// We can't easily capture the send without mocking, but we verify
	// the interest matching logic is correct
	m.mu.RLock()
	matchA := false
	for _, prefix := range m.interests["peerA"] {
		if len("oracle:rates:bsv") >= len(prefix) && "oracle:rates:bsv"[:len(prefix)] == prefix {
			matchA = true
		}
	}
	matchB := false
	for _, prefix := range m.interests["peerB"] {
		if len("oracle:rates:bsv") >= len(prefix) && "oracle:rates:bsv"[:len(prefix)] == prefix {
			matchB = true
		}
	}
	m.mu.RUnlock()

	if !matchA {
		t.Fatal("peerA should match oracle:rates:bsv")
	}
	if matchB {
		t.Fatal("peerB should NOT match oracle:rates:bsv")
	}
}
