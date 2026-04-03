package messaging

import (
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir, 3600) // 1 hour TTL
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSendAndList(t *testing.T) {
	s := testStore(t)

	id, err := s.Send(&Message{
		Sender:     "02aaa",
		Recipient:  "02bbb",
		MessageBox: "inbox",
		Body:       "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("expected non-empty message ID")
	}

	msgs, err := s.List("02bbb", "inbox")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Body != "hello" {
		t.Fatalf("expected body 'hello', got %q", msgs[0].Body)
	}
	if msgs[0].Sender != "02aaa" {
		t.Fatalf("expected sender 02aaa, got %s", msgs[0].Sender)
	}
}

func TestListFiltersMessageBox(t *testing.T) {
	s := testStore(t)

	s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "a"})
	s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "payment", Body: "b"})
	s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "c"})

	inbox, _ := s.List("02b", "inbox")
	if len(inbox) != 2 {
		t.Fatalf("expected 2 inbox messages, got %d", len(inbox))
	}
	payment, _ := s.List("02b", "payment")
	if len(payment) != 1 {
		t.Fatalf("expected 1 payment message, got %d", len(payment))
	}
}

func TestListDoesNotCrossRecipients(t *testing.T) {
	s := testStore(t)

	s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "for-b"})
	s.Send(&Message{Sender: "02a", Recipient: "02c", MessageBox: "inbox", Body: "for-c"})

	bMsgs, _ := s.List("02b", "inbox")
	if len(bMsgs) != 1 || bMsgs[0].Body != "for-b" {
		t.Fatalf("recipient b got wrong messages: %v", bMsgs)
	}
	cMsgs, _ := s.List("02c", "inbox")
	if len(cMsgs) != 1 || cMsgs[0].Body != "for-c" {
		t.Fatalf("recipient c got wrong messages: %v", cMsgs)
	}
}

func TestAcknowledge(t *testing.T) {
	s := testStore(t)

	id1, _ := s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "first"})
	id2, _ := s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "second"})

	n, err := s.Acknowledge("02b", []string{id1})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}

	msgs, _ := s.List("02b", "inbox")
	if len(msgs) != 1 || msgs[0].MessageID != id2 {
		t.Fatalf("expected only second message remaining, got %v", msgs)
	}
}

func TestAcknowledgeWrongRecipient(t *testing.T) {
	s := testStore(t)

	id, _ := s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "x"})

	// Try to acknowledge as wrong recipient
	n, _ := s.Acknowledge("02c", []string{id})
	if n != 0 {
		t.Fatalf("expected 0 deleted for wrong recipient, got %d", n)
	}

	// Original still exists
	msgs, _ := s.List("02b", "inbox")
	if len(msgs) != 1 {
		t.Fatal("message should still exist")
	}
}

func TestSendRejectsEmpty(t *testing.T) {
	s := testStore(t)

	if _, err := s.Send(&Message{Sender: "02a", MessageBox: "inbox", Body: "x"}); err == nil {
		t.Fatal("expected error for empty recipient")
	}
	if _, err := s.Send(&Message{Sender: "02a", Recipient: "02b", Body: "x"}); err == nil {
		t.Fatal("expected error for empty messageBox")
	}
	if _, err := s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox"}); err == nil {
		t.Fatal("expected error for empty body")
	}
}

func TestCount(t *testing.T) {
	s := testStore(t)

	if s.Count() != 0 {
		t.Fatal("expected 0 messages initially")
	}

	s.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "a"})
	s.Send(&Message{Sender: "02a", Recipient: "02c", MessageBox: "inbox", Body: "b"})

	if s.Count() != 2 {
		t.Fatalf("expected 2 messages, got %d", s.Count())
	}
}

func TestExpireOld(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir, 1) // 1 second TTL
	defer s.Close()

	s.Send(&Message{
		Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "old",
		Timestamp: 1000, // very old
	})
	s.Send(&Message{
		Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "new",
		// Timestamp will be set to now
	})

	n := s.ExpireOld()
	if n != 1 {
		t.Fatalf("expected 1 expired, got %d", n)
	}

	msgs, _ := s.List("02b", "inbox")
	if len(msgs) != 1 || msgs[0].Body != "new" {
		t.Fatalf("expected only 'new' message remaining, got %v", msgs)
	}
}

func TestIDPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()

	s1, _ := NewStore(dir, 3600)
	s1.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "a"})
	id1, _ := s1.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "b"})
	s1.Close()

	s2, _ := NewStore(dir, 3600)
	defer s2.Close()
	id2, _ := s2.Send(&Message{Sender: "02a", Recipient: "02b", MessageBox: "inbox", Body: "c"})

	if id2 <= id1 {
		t.Fatalf("expected id2 (%s) > id1 (%s) after reopen", id2, id1)
	}
}
