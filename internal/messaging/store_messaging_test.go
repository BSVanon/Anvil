package messaging

import (
	"testing"
)

func TestDeliverPreservesID(t *testing.T) {
	s := testStore(t)

	msg := &Message{
		MessageID:  "remote-42",
		Sender:     "02aaa",
		Recipient:  "02bbb",
		MessageBox: "inbox",
		Body:       "forwarded",
		Timestamp:  1700000000,
	}
	ok, err := s.Deliver(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected delivery to succeed")
	}

	msgs, _ := s.List("02bbb", "inbox")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].MessageID != "remote-42" {
		t.Fatalf("expected preserved ID 'remote-42', got %q", msgs[0].MessageID)
	}
}

func TestDeliverDeduplicates(t *testing.T) {
	s := testStore(t)

	msg := &Message{
		MessageID:  "dedup-1",
		Sender:     "02aaa",
		Recipient:  "02bbb",
		MessageBox: "inbox",
		Body:       "first",
	}

	ok1, _ := s.Deliver(msg)
	if !ok1 {
		t.Fatal("first delivery should succeed")
	}

	// Second delivery of same ID should be rejected
	ok2, _ := s.Deliver(msg)
	if ok2 {
		t.Fatal("duplicate delivery should return false")
	}

	msgs, _ := s.List("02bbb", "inbox")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message after dedup, got %d", len(msgs))
	}
}

func TestDeliverRejectsEmpty(t *testing.T) {
	s := testStore(t)

	// Missing messageID
	_, err := s.Deliver(&Message{Recipient: "02b", MessageBox: "inbox", Body: "x"})
	if err == nil {
		t.Fatal("expected error for empty messageID")
	}

	// Missing recipient
	_, err = s.Deliver(&Message{MessageID: "1", MessageBox: "inbox", Body: "x"})
	if err == nil {
		t.Fatal("expected error for empty recipient")
	}

	// Missing body
	_, err = s.Deliver(&Message{MessageID: "1", Recipient: "02b", MessageBox: "inbox"})
	if err == nil {
		t.Fatal("expected error for empty body")
	}
}
