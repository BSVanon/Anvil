package gossip

import (
	"encoding/json"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestProtocolEncodeDecode(t *testing.T) {
	// Encode a topics message
	encoded, err := Encode(MsgTopics, TopicsPayload{Prefixes: []string{"oracle:", "forge:"}})
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
	h1 := envelope.HashEnvelope("oracle:rates", "02abc", 1700000000)
	h2 := envelope.HashEnvelope("oracle:rates", "02abc", 1700000000)
	h3 := envelope.HashEnvelope("oracle:rates", "02abc", 1700000001)

	if h1 != h2 {
		t.Fatal("same inputs should produce same hash")
	}
	if h1 == h3 {
		t.Fatal("different timestamp should produce different hash")
	}
}

func TestManagerNewAndPeerCount(t *testing.T) {
	m := NewManager(ManagerConfig{
		LocalInterests: []string{"oracle:", "forge:"},
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
	m.interests["peer2"] = []string{"forge:"}
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
