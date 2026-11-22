package messaging

import "testing"

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
