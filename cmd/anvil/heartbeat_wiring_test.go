package main

import (
	"os"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// newTestEnvelopeStore builds a real, on-disk envelope.Store for a test —
// never a stub — so the heartbeat wiring tests below exercise the actual
// accessor the wrapper functions resolve to.
func newTestEnvelopeStore(t *testing.T) *envelope.Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "anvil-heartbeat-wiring-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func mustIngest(t *testing.T, store *envelope.Store, key *ec.PrivateKey, topic string, private bool) {
	t.Helper()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     topic,
		Payload:   `{"v":1}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
		Private:   private,
	}
	env.Sign(key)
	if err := store.Ingest(env); err != nil {
		t.Fatalf("ingest %s: %v", topic, err)
	}
}

// TestHeartbeatTopicsFnUsesPublicAccessor proves the actual main.go wiring
// — heartbeatTopicsFn bound to a real store — never names a topic that has
// only private envelopes, the same guarantee envelope.Store.PublicTopics
// gives directly. A test that only ever calls a stub TopicsFn can't catch a
// regression where main.go's own wiring is changed back to the unfiltered
// Store.Topics; this one calls the real wrapper against a real store.
func TestHeartbeatTopicsFnUsesPublicAccessor(t *testing.T) {
	store := newTestEnvelopeStore(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	mustIngest(t, store, key, "lacriada:household-x", true)
	mustIngest(t, store, key, "oracle:rates:bsv", false)

	topicsFn := heartbeatTopicsFn(store)
	topics := topicsFn()

	if _, ok := topics["lacriada:household-x"]; ok {
		t.Fatalf("heartbeatTopicsFn must not name a private-only topic, got %v", topics)
	}
	if _, ok := topics["oracle:rates:bsv"]; !ok {
		t.Fatalf("heartbeatTopicsFn should list the public topic, got %v", topics)
	}
}

// TestHeartbeatPrivateOnlyTopicsFnUsesRealAccessor proves the main.go
// wiring for PrivateOnlyTopicsFn — bound to a real store — reports a
// topic with only private envelopes as private-only, and a public topic as
// not. Same real-store rationale as TestHeartbeatTopicsFnUsesPublicAccessor.
func TestHeartbeatPrivateOnlyTopicsFnUsesRealAccessor(t *testing.T) {
	store := newTestEnvelopeStore(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	mustIngest(t, store, key, "lacriada:household-x", true)
	mustIngest(t, store, key, "oracle:rates:bsv", false)

	privateOnlyFn := heartbeatPrivateOnlyTopicsFn(store)
	privateOnly := privateOnlyFn()

	if _, ok := privateOnly["lacriada:household-x"]; !ok {
		t.Fatalf("heartbeatPrivateOnlyTopicsFn should report the private-only topic, got %v", privateOnly)
	}
	if _, ok := privateOnly["oracle:rates:bsv"]; ok {
		t.Fatalf("heartbeatPrivateOnlyTopicsFn must not report a public topic as private-only, got %v", privateOnly)
	}
}
