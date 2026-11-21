package envelope

import (
	"fmt"
	"os"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// QueryExactTopic returns only the envelopes on exactly the topic, durable
// and ephemeral, newest-first and limited after filtering, while
// QueryByTopic keeps its prefix match. "t:t" also shares the durable key
// prefix "d:t:t:" with "t"'s own keys ("d:" + topic + ":" + Key(), where
// Key starts with the topic), so a key prefix alone cannot tell them apart.
func TestQueryExactTopic(t *testing.T) {
	dir, err := os.MkdirTemp("", "anvil-envelope-exact-*")
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
	now := time.Now().Unix()
	put := func(topic, payload string, ts int64, durable bool) {
		t.Helper()
		env := &Envelope{Type: "data", Topic: topic, Payload: payload, Timestamp: ts, Durable: durable}
		if !durable {
			env.TTL = 60
		}
		env.Sign(key)
		if err := store.Ingest(env); err != nil {
			t.Fatalf("ingest %s: %v", topic, err)
		}
	}
	put("t", `{"n":1}`, now-30, true)
	put("t", `{"n":2}`, now-20, true)
	put("t", `{"n":3}`, now-10, false)
	put("t:x", `{"sub":1}`, now, true)
	put("t:t", `{"sub":2}`, now, true)

	exact, err := store.QueryExactTopic("t", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(exact) != 3 {
		t.Fatalf("want t's 3 envelopes, got %d", len(exact))
	}
	for i, env := range exact {
		if env.Topic != "t" {
			t.Fatalf("envelope %d is on %q, want only t", i, env.Topic)
		}
		if i > 0 && exact[i-1].Timestamp < env.Timestamp {
			t.Fatal("want newest-first")
		}
	}
	if limited, _ := store.QueryExactTopic("t", 2); len(limited) != 2 || limited[0].Payload != `{"n":3}` {
		t.Fatalf("want the 2 newest of t's own envelopes, got %d", len(limited))
	}
	if prefix, _ := store.QueryByTopic("t", 0); len(prefix) != 5 {
		t.Fatalf("QueryByTopic keeps its prefix match: want 5, got %d", len(prefix))
	}
}

func TestPublicPrefixCursorCrossesEqualTimestamps(t *testing.T) {
	store, err := NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 101; i++ {
		env := &Envelope{
			Type: "data", Topic: "catchup:topic", Payload: fmt.Sprintf(`{"n":%d}`, i),
			Durable: true, Timestamp: 100,
		}
		env.Sign(key)
		if err := store.Ingest(env); err != nil {
			t.Fatal(err)
		}
	}

	first, err := store.QueryPublicTopicPrefix("catchup:topic", 100, PageCursor{})
	if err != nil || len(first) != 100 {
		t.Fatalf("first page = %d, %v; want 100", len(first), err)
	}
	second, err := store.QueryPublicTopicPrefix("catchup:topic", 100, CursorFor(first[99]))
	if err != nil || len(second) != 1 {
		t.Fatalf("second page = %d, %v; want 1", len(second), err)
	}
	seen := make(map[string]bool, 101)
	for _, env := range append(first, second...) {
		seen[env.Payload] = true
	}
	if len(seen) != 101 {
		t.Fatalf("compound cursor returned %d unique envelopes, want 101", len(seen))
	}
}
