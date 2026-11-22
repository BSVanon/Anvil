package messaging

import (
	"testing"
	"time"
)

func TestAcknowledgedMessageCannotBeDeliveredAgain(t *testing.T) {
	store, err := NewStore(t.TempDir(), Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sender, recipient := testIdentity(t), testIdentity(t)
	message := &Message{
		MessageID: "late-forward", Sender: sender, Recipient: recipient,
		MessageBox: "inbox", Body: "ciphertext", Timestamp: 1,
	}
	if inserted, err := store.Deliver(message, sender); err != nil || !inserted {
		t.Fatalf("first delivery = %v, %v", inserted, err)
	}
	if n, err := store.Acknowledge(recipient, []string{message.MessageID}); err != nil || n != 1 {
		t.Fatalf("acknowledge = %d, %v", n, err)
	}
	if inserted, err := store.Deliver(message, sender); err != nil || inserted {
		t.Fatalf("late delivery = %v, %v", inserted, err)
	}
}

func TestAcknowledgementExpiryIsChunkedAndReconnectSkipsOverdueRows(t *testing.T) {
	oldChunk := ackTombstoneExpiryChunk
	ackTombstoneExpiryChunk = 10
	defer func() { ackTombstoneExpiryChunk = oldChunk }()
	now := time.Unix(2_000_000_000, 0)
	store, err := NewStore(t.TempDir(), Options{TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.now = func() time.Time { return now }
	recipient := testIdentity(t)
	store.writeMu.Lock()
	for i := 0; i < 50; i++ {
		if err := store.putAckTombstoneLocked(recipient, string(rune('a'+i)), now.Unix()); err != nil {
			store.writeMu.Unlock()
			t.Fatal(err)
		}
	}
	store.writeMu.Unlock()
	now = now.Add(61 * time.Second)
	store.expireAckTombstones()
	if total, err := readUint64(store.db, keyAckTotal); err != nil || total != 40 {
		t.Fatalf("total after one expiry invocation = %d, %v; want 40", total, err)
	}
	message := &Message{
		MessageID: "ack-expiry-progress", Sender: testIdentity(t), Recipient: testIdentity(t),
		MessageBox: "inbox", Body: "ciphertext", Timestamp: now.Unix(),
	}
	if inserted, err := store.Deliver(message, message.Sender); err != nil || !inserted {
		t.Fatalf("delivery between expiry chunks = %v, %v", inserted, err)
	}
	var replayed []string
	if err := store.ForEachAcknowledgementPage(recipient, 100, func(page []string) error {
		replayed = append(replayed, page...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 0 {
		t.Fatalf("reconnect returned %d expired acknowledgement rows", len(replayed))
	}
	if total, err := readUint64(store.db, keyAckTotal); err != nil || total != 30 {
		t.Fatalf("reconnect expiry removed more than one chunk: total=%d error=%v", total, err)
	}
}
