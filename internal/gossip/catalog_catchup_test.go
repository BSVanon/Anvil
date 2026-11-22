package gossip

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func catalogEnvelope(key *ec.PrivateKey, timestamp int64, payload string) *envelope.Envelope {
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "anvil:catalog",
		Payload:   payload,
		Durable:   true,
		Timestamp: timestamp,
	}
	env.Sign(key)
	return env
}

func deliverCatalogCatchup(t *testing.T, manager *Manager, env *envelope.Envelope) {
	t.Helper()
	raw, err := json.Marshal(DataResponsePayload{
		Topic:     "anvil:catalog",
		Envelopes: []*envelope.Envelope{env},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.onDataResponse("peer", nil, raw); err != nil {
		t.Fatal(err)
	}
}

func requireOnlyCatalog(t *testing.T, store *envelope.Store, want *envelope.Envelope) {
	t.Helper()
	entries, err := store.QueryExactTopic("anvil:catalog", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("catalog entries = %d, want 1", len(entries))
	}
	if entries[0].Timestamp != want.Timestamp || entries[0].Payload != want.Payload {
		t.Fatalf("catalog entry = timestamp %d payload %q, want timestamp %d payload %q",
			entries[0].Timestamp, entries[0].Payload, want.Timestamp, want.Payload)
	}
}

func TestCatalogCatchupDoesNotKeepOlderEntry(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	newer := catalogEnvelope(key, 200, `{"version":2}`)
	older := catalogEnvelope(key, 100, `{"version":1}`)
	if err := store.Ingest(newer); err != nil {
		t.Fatal(err)
	}

	deliverCatalogCatchup(t, manager, older)
	requireOnlyCatalog(t, store, newer)
}

func TestCatalogCatchupDoesNotOverwriteNewerEntryWithSamePayload(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	newer := catalogEnvelope(key, 200, `{"version":2}`)
	older := catalogEnvelope(key, 100, `{"version":2}`)
	if newer.Key() != older.Key() {
		t.Fatalf("test envelopes use different durable keys: %q != %q", newer.Key(), older.Key())
	}
	if err := store.Ingest(newer); err != nil {
		t.Fatal(err)
	}

	deliverCatalogCatchup(t, manager, older)
	requireOnlyCatalog(t, store, newer)
}

func TestCatalogLiveDoesNotOverwriteNewerEntryWithSamePayload(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	newer := catalogEnvelope(key, 200, `{"version":2}`)
	older := catalogEnvelope(key, 100, `{"version":2}`)
	if err := store.Ingest(newer); err != nil {
		t.Fatal(err)
	}
	raw, err := older.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.onData("peer", raw); err != nil {
		t.Fatal(err)
	}
	requireOnlyCatalog(t, store, newer)
}

func TestCatalogCatchupKeepsNewestArrival(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	older := catalogEnvelope(key, 100, `{"version":1}`)
	newer := catalogEnvelope(key, 200, `{"version":2}`)

	deliverCatalogCatchup(t, manager, older)
	deliverCatalogCatchup(t, manager, newer)
	requireOnlyCatalog(t, store, newer)
}

func TestCatalogCatchupIngestFailureKeepsStoredEntry(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	stored := catalogEnvelope(key, 100, `{"version":1}`)
	rejected := catalogEnvelope(key, 200, strings.Repeat("x", 64))
	if err := store.Ingest(stored); err != nil {
		t.Fatal(err)
	}

	deliverCatalogCatchup(t, manager, rejected)
	requireOnlyCatalog(t, store, stored)
}

func TestCatalogCatchupCollapsesPubkeyCaseVariants(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	original := catalogEnvelope(key, 100, `{"version":1}`)
	alias := *original
	alias.Pubkey = strings.ToUpper(alias.Pubkey)

	deliverCatalogCatchup(t, manager, original)
	deliverCatalogCatchup(t, manager, &alias)
	requireOnlyCatalog(t, store, original)
}

func TestCatalogCatchupRemovesEveryOlderEntry(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	entries := []*envelope.Envelope{
		catalogEnvelope(key, 1, `{"version":"a"}`),
		catalogEnvelope(key, 1, `{"version":"b"}`),
		catalogEnvelope(key, 1, `{"version":"c"}`),
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key() < entries[j].Key() })
	oldest, middle, newest := entries[0], entries[1], entries[2]
	oldest.Timestamp, middle.Timestamp, newest.Timestamp = 100, 200, 300
	oldest.Sign(key)
	middle.Sign(key)
	newest.Sign(key)
	if err := store.Ingest(oldest); err != nil {
		t.Fatal(err)
	}
	if err := store.Ingest(newest); err != nil {
		t.Fatal(err)
	}

	deliverCatalogCatchup(t, manager, middle)
	requireOnlyCatalog(t, store, newest)
}

func TestCatalogCatchupEqualTimestampHasDeterministicWinner(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	left := catalogEnvelope(key, 100, `{"version":"left"}`)
	right := catalogEnvelope(key, 100, `{"version":"right"}`)
	winner, loser := left, right
	if envelope.CursorFor(right).ID < envelope.CursorFor(left).ID {
		winner, loser = right, left
	}

	deliverCatalogCatchup(t, manager, winner)
	deliverCatalogCatchup(t, manager, loser)
	requireOnlyCatalog(t, store, winner)
}

func TestCatalogCatchupConcurrentDuplicateKeepsExactCount(t *testing.T) {
	store, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := NewManager(ManagerConfig{Store: store})
	defer manager.Stop()
	key, _ := ec.NewPrivateKey()
	env := catalogEnvelope(key, 100, `{"version":1}`)
	raw, err := json.Marshal(DataResponsePayload{
		Topic: "anvil:catalog", Envelopes: []*envelope.Envelope{env},
	})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_ = manager.onDataResponse("peer", nil, raw)
		}()
	}
	close(start)
	workers.Wait()

	if got := store.CountDurable(); got != 1 {
		t.Fatalf("durable records = %d, want 1", got)
	}
	if got := store.PublicCountDurable(); got != 1 {
		t.Fatalf("cached public durable count = %d, want 1", got)
	}
}
