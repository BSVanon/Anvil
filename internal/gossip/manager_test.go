package gossip

import (
	"encoding/json"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestProtocolEncodeDecode(t *testing.T) {
	// Encode a topics message
	encoded, err := Encode(MsgTopics, TopicsPayload{Prefixes: []string{"oracle:", "anvil:"}})
	if err != nil {
		t.Fatal(err)
	}

	msg, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MsgTopics {
		t.Fatalf("expected type %q, got %q", MsgTopics, msg.Type)
	}

	var tp TopicsPayload
	if err := json.Unmarshal(msg.Data, &tp); err != nil {
		t.Fatal(err)
	}
	if len(tp.Prefixes) != 2 || tp.Prefixes[0] != "oracle:" {
		t.Fatalf("unexpected prefixes: %v", tp.Prefixes)
	}
}

func TestProtocolEncodeDecodeEnvelope(t *testing.T) {
	// Create and sign a real envelope
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:gossip",
		Payload:   `{"msg":"hello mesh"}`,
		TTL:       60,
		Timestamp: 1700000000,
	}
	env.Sign(key)

	// Encode as data message
	raw, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(MsgData, json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}

	// Decode
	msg, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MsgData {
		t.Fatalf("expected type %q, got %q", MsgData, msg.Type)
	}

	decoded, err := envelope.UnmarshalEnvelope(msg.Data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Topic != "test:gossip" {
		t.Fatalf("expected topic test:gossip, got %s", decoded.Topic)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("decoded envelope should be valid: %v", err)
	}
}

func TestHashEnvelopeDedup(t *testing.T) {
	h1 := envelope.HashEnvelope("oracle:rates", "02abc", "payload1", 1700000000)
	h2 := envelope.HashEnvelope("oracle:rates", "02abc", "payload1", 1700000000)
	h3 := envelope.HashEnvelope("oracle:rates", "02abc", "payload1", 1700000001)
	h4 := envelope.HashEnvelope("oracle:rates", "02abc", "payload2", 1700000000)

	if h1 != h2 {
		t.Fatal("same inputs should produce same hash")
	}
	if h1 == h3 {
		t.Fatal("different timestamp should produce different hash")
	}
	if h1 == h4 {
		t.Fatal("different payload should produce different hash — this was the dedup collision bug")
	}
}

func TestManagerNewAndPeerCount(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalInterests: []string{"oracle:", "anvil:"},
		MaxSeen:        100,
	})

	if m.PeerCount() != 0 {
		t.Fatalf("expected 0 peers, got %d", m.PeerCount())
	}

	if len(m.localInterests) != 2 {
		t.Fatalf("expected 2 interests, got %d", len(m.localInterests))
	}
}

func TestManagerTopicInterestRouting(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalInterests: []string{"oracle:"},
		MaxSeen:        100,
	})

	// Simulate a peer declaring interest
	m.mu.Lock()
	m.interests["peer1"] = []string{"oracle:rates:"}
	m.interests["peer2"] = []string{"anvil:"}
	m.mu.Unlock()

	// Check that topic matching works
	m.mu.RLock()
	peer1Match := false
	for _, prefix := range m.interests["peer1"] {
		if len("oracle:rates:bsv") >= len(prefix) && "oracle:rates:bsv"[:len(prefix)] == prefix {
			peer1Match = true
		}
	}
	peer2Match := false
	for _, prefix := range m.interests["peer2"] {
		if len("oracle:rates:bsv") >= len(prefix) && "oracle:rates:bsv"[:len(prefix)] == prefix {
			peer2Match = true
		}
	}
	m.mu.RUnlock()

	if !peer1Match {
		t.Fatal("peer1 should match oracle:rates:bsv")
	}
	if peer2Match {
		t.Fatal("peer2 should NOT match oracle:rates:bsv")
	}
}

func TestNoGossipEnvelopeNotBroadcast(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalInterests: []string{""},
		MaxSeen:        100,
	})

	// Create a no_gossip envelope
	env := &envelope.Envelope{
		Type:     "data",
		Topic:    "test:secret",
		Payload:  "hidden",
		Pubkey:   "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		TTL:      60,
		NoGossip: true,
	}

	// BroadcastEnvelope should be a no-op for no_gossip envelopes
	m.BroadcastEnvelope(env)

	// If it was broadcast, it would appear in the seen map.
	// With NoGossip=true, BroadcastEnvelope returns before marking as seen.
	m.seenMu.Lock()
	_, wasSeen := m.seen[envelope.HashEnvelope(env.Topic, env.Pubkey, env.Payload, env.Timestamp)]
	m.seenMu.Unlock()

	if wasSeen {
		t.Fatal("no_gossip envelope should NOT be broadcast or marked as seen")
	}
}

func TestCatchUpTopicsConfig(t *testing.T) {
	topics := []string{"anvil:catalog", "mesh:heartbeat", "mesh:blocks"}
	m := NewManager(ManagerConfig{
		LocalInterests: []string{""},
		MaxSeen:        100,
		CatchUpTopics:  topics,
	})

	if len(m.catchUpTopics) != 3 {
		t.Fatalf("expected 3 catch-up topics, got %d", len(m.catchUpTopics))
	}
	if m.catchUpTopics[0] != "anvil:catalog" {
		t.Fatalf("expected first topic anvil:catalog, got %s", m.catchUpTopics[0])
	}
}

func TestCatchUpEncodesDataRequest(t *testing.T) {
	// Verify the catch-up protocol message encodes correctly
	payload, err := Encode(MsgDataRequest, DataRequestPayload{
		Topic: "anvil:catalog",
		Limit: 50,
	})
	if err != nil {
		t.Fatal(err)
	}

	msg, err := Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MsgDataRequest {
		t.Fatalf("expected type %q, got %q", MsgDataRequest, msg.Type)
	}

	var req DataRequestPayload
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		t.Fatal(err)
	}
	if req.Topic != "anvil:catalog" {
		t.Fatalf("expected topic anvil:catalog, got %s", req.Topic)
	}
	if req.Limit != 50 {
		t.Fatalf("expected limit 50, got %d", req.Limit)
	}
}

func TestGossipEnvelopeIsBroadcast(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalInterests: []string{""},
		MaxSeen:        100,
	})

	env := &envelope.Envelope{
		Type:     "data",
		Topic:    "test:public",
		Payload:  "visible",
		Pubkey:   "0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66",
		TTL:      60,
		NoGossip: false,
	}

	m.BroadcastEnvelope(env)

	m.seenMu.Lock()
	_, wasSeen := m.seen[envelope.HashEnvelope(env.Topic, env.Pubkey, env.Payload, env.Timestamp)]
	m.seenMu.Unlock()

	if !wasSeen {
		t.Fatal("normal envelope SHOULD be broadcast and marked as seen")
	}
}
