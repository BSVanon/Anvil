package envelope

import (
	"fmt"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func publicSummaryAllocs(t *testing.T, privateCount int) float64 {
	t.Helper()
	store, err := NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for i := 0; i < privateCount; i++ {
		env := &Envelope{
			Type: "data", Topic: "private:metadata", Payload: fmt.Sprintf(`{"n":%d}`, i),
			Durable: true, Timestamp: now + int64(i), Private: true,
		}
		env.Sign(key)
		if err := store.Ingest(env); err != nil {
			t.Fatal(err)
		}
	}
	public := &Envelope{
		Type: "data", Topic: "public:metadata", Payload: `{"ok":true}`,
		Durable: true, Timestamp: now,
	}
	public.Sign(key)
	if err := store.Ingest(public); err != nil {
		t.Fatal(err)
	}

	return testing.AllocsPerRun(2, func() {
		counts, latest := store.PublicTopicSummary()
		if counts["public:metadata"] != 1 || latest["public:metadata"] != now {
			t.Fatalf("wrong public summary: %v %v", counts, latest)
		}
	})
}

func TestPublicSummaryWorkDoesNotScaleWithPrivateStore(t *testing.T) {
	baseline := publicSummaryAllocs(t, 0)
	withPrivate := publicSummaryAllocs(t, 200)
	if withPrivate > baseline+100 {
		t.Fatalf("allocations scale with private store: baseline %.0f, with private records %.0f", baseline, withPrivate)
	}
}

func TestPublicSummaryUpdatesAfterDurableDelete(t *testing.T) {
	store, err := NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	key, _ := ec.NewPrivateKey()
	older := &Envelope{Type: "data", Topic: "summary:delete", Payload: `{"n":1}`, Durable: true, Timestamp: 10}
	newer := &Envelope{Type: "data", Topic: "summary:delete", Payload: `{"n":2}`, Durable: true, Timestamp: 20}
	older.Sign(key)
	newer.Sign(key)
	if err := store.Ingest(older); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(newer); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.Delete(newer.Topic, newer.Key()); err != nil || !deleted {
		t.Fatalf("delete newest = %v, %v", deleted, err)
	}
	counts, latest := store.PublicTopicSummary()
	if counts[older.Topic] != 1 || latest[older.Topic] != older.Timestamp {
		t.Fatalf("summary after delete = %v %v", counts, latest)
	}
}
