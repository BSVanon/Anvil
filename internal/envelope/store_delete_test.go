package envelope

import (
	"os"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestStoreDeleteRemovesDurableAndEphemeral(t *testing.T) {
	dir, err := os.MkdirTemp("", "anvil-envelope-delete-*")
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

	durable := &Envelope{
		Type:      "data",
		Topic:     "anvil:catalog",
		Payload:   `{"name":"durable"}`,
		TTL:       0,
		Durable:   true,
		Timestamp: time.Now().Unix(),
	}
	durable.Sign(key)
	if err := store.Ingest(durable); err != nil {
		t.Fatal(err)
	}

	ephemeral := &Envelope{
		Type:      "data",
		Topic:     "oracle:rates:bsv",
		Payload:   `{"rate":42}`,
		TTL:       60,
		Timestamp: time.Now().Unix() + 1,
	}
	ephemeral.Sign(key)
	if err := store.Ingest(ephemeral); err != nil {
		t.Fatal(err)
	}

	deleted, err := store.Delete(durable.Topic, durable.Key())
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("expected durable envelope to be deleted")
	}
	if got := store.CountDurable(); got != 0 {
		t.Fatalf("expected 0 durable envelopes after delete, got %d", got)
	}

	deleted, err = store.Delete(ephemeral.Topic, ephemeral.Key())
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("expected ephemeral envelope to be deleted")
	}
	if got := store.CountEphemeral(); got != 0 {
		t.Fatalf("expected 0 ephemeral envelopes after delete, got %d", got)
	}
}
