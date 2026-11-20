package gossip

// Unit tests for the three mesh health counters exposed on GET /stats
// (dedup_evictions, duplicate_arrivals, catchup_truncated). Each test
// drives the exact condition that increments its counter.

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// TestDuplicateArrivalsCounter drives onData with the same signed envelope
// twice: the second arrival must be discarded as already seen and counted.
func TestDuplicateArrivalsCounter(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-gossip-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	m := NewManager(ManagerConfig{Store: store, MaxSeen: 100})
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

	if got := m.DuplicateArrivals(); got != 0 {
		t.Fatalf("expected 0 duplicate arrivals before any traffic, got %d", got)
	}

	if err := m.onData("sender1", json.RawMessage(raw)); err != nil {
		t.Fatalf("first onData: %v", err)
	}
	if got := m.DuplicateArrivals(); got != 0 {
		t.Fatalf("first arrival must not count as a duplicate, got %d", got)
	}

	if err := m.onData("sender1", json.RawMessage(raw)); err != nil {
		t.Fatalf("second onData: %v", err)
	}
	if got := m.DuplicateArrivals(); got != 1 {
		t.Fatalf("expected 1 duplicate arrival after resending the same envelope, got %d", got)
	}
}

// TestDedupEvictionsCounter drives onData with enough distinct envelopes to
// overflow a small maxSeen, forcing the halving eviction to run.
func TestDedupEvictionsCounter(t *testing.T) {
	dir, _ := os.MkdirTemp("", "anvil-gossip-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const maxSeen = 4
	m := NewManager(ManagerConfig{Store: store, MaxSeen: maxSeen})
	defer m.Stop()

	key, _ := ec.NewPrivateKey()
	if got := m.DedupEvictions(); got != 0 {
		t.Fatalf("expected 0 dedup evictions before any traffic, got %d", got)
	}

	// maxSeen+1 distinct envelopes guarantee at least one eviction pass:
	// onData evicts once len(m.seen) >= maxSeen.
	for i := 0; i < maxSeen+1; i++ {
		env := &envelope.Envelope{
			Type:      "data",
			Topic:     "oracle:rates:bsv",
			Payload:   fmt.Sprintf(`{"rate":%d}`, i),
			TTL:       60,
			Timestamp: time.Now().Unix(),
		}
		env.Sign(key)
		raw, _ := env.Marshal()
		if err := m.onData("sender1", json.RawMessage(raw)); err != nil {
			t.Fatalf("onData %d: %v", i, err)
		}
	}

	if got := m.DedupEvictions(); got == 0 {
		t.Fatal("expected at least one dedup eviction once maxSeen was exceeded")
	}
}

// TestCatchupTruncatedCounter drives onDataResponse for a peer+topic that
// has already used its maxCatchUpRounds budget: a HasMore=true reply must
// be counted as a truncation rather than triggering another round.
func TestCatchupTruncatedCounter(t *testing.T) {
	m := NewManager(ManagerConfig{MaxSeen: 100})
	defer m.Stop()

	if got := m.CatchupTruncated(); got != 0 {
		t.Fatalf("expected 0 catchup_truncated before any traffic, got %d", got)
	}

	const senderPK = "sender1"
	const topic = "anvil:catalog"
	roundKey := senderPK + ":" + topic
	m.catchUpRounds = map[string]int{roundKey: maxCatchUpRounds}

	key, _ := ec.NewPrivateKey()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     topic,
		Payload:   `{"n":1}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)

	resp := DataResponsePayload{
		Topic:     topic,
		Envelopes: []*envelope.Envelope{env},
		HasMore:   true,
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	if err := m.onDataResponse(senderPK, nil, json.RawMessage(raw)); err != nil {
		t.Fatalf("onDataResponse: %v", err)
	}

	if got := m.CatchupTruncated(); got != 1 {
		t.Fatalf("expected 1 catchup_truncated after exceeding the round budget, got %d", got)
	}

	// The round counter itself must not advance once truncated.
	if m.catchUpRounds[roundKey] != maxCatchUpRounds {
		t.Fatalf("round counter must not advance once truncated, got %d", m.catchUpRounds[roundKey])
	}
}
