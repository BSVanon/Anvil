package envelope

import (
	"os"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// TestPublicTopicsExcludesPrivateOnlyTopic: a topic with only private
// envelopes is absent from PublicTopics entirely — not present with a zero
// count, absent as a key. This is the primitive every metadata route
// relies on to avoid naming a private-only topic to an unauthenticated
// caller or a mesh peer.
func TestPublicTopicsExcludesPrivateOnlyTopic(t *testing.T) {
	dir, err := os.MkdirTemp("", "anvil-envelope-public-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	store, err := NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	privateOnly := &Envelope{
		Type: "data", Topic: "lacriada:household-x", Payload: `{"secret":"sealed"}`,
		TTL: 60, Timestamp: time.Now().Unix(), Private: true,
	}
	privateOnly.Sign(key)
	if err := store.Ingest(privateOnly); err != nil {
		t.Fatal(err)
	}

	public := &Envelope{
		Type: "data", Topic: "oracle:rates:bsv", Payload: `{"rate":42}`,
		TTL: 60, Timestamp: time.Now().Unix(),
	}
	public.Sign(key)
	if err := store.Ingest(public); err != nil {
		t.Fatal(err)
	}

	topics := store.PublicTopics()
	if _, ok := topics["lacriada:household-x"]; ok {
		t.Fatalf("PublicTopics must not list a private-only topic, got %v", topics)
	}
	if count, ok := topics["oracle:rates:bsv"]; !ok || count != 1 {
		t.Fatalf("PublicTopics should list the public topic with count 1, got %v", topics)
	}

	// Topics (the unfiltered accessor every metadata route must NOT use
	// directly) still shows both — proving the two are genuinely different
	// and the fix is PublicTopics, not a change to Topics' semantics.
	all := store.Topics()
	if _, ok := all["lacriada:household-x"]; !ok {
		t.Fatalf("Topics (unfiltered) should still include the private topic, got %v", all)
	}
}
