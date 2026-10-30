package messaging

import (
	"fmt"
	"testing"
)

func TestListExaminesOnlyExactBox(t *testing.T) {
	s := testStore(t, Options{MaxPairMessages: 20000, MaxStoreMessages: 20000})
	sender, recipient := testIdentity(t), testIdentity(t)
	for i := 0; i < 10000; i++ {
		msg := &Message{MessageID: fmt.Sprintf("junk-%d", i), Sender: sender, Recipient: recipient, MessageBox: fmt.Sprintf("other-%d", i%17), Body: "x"}
		if ok, err := s.Deliver(msg, "sender"); err != nil || !ok {
			t.Fatalf("junk %d: %v, %v", i, ok, err)
		}
	}
	for i := 0; i < 3; i++ {
		msg := &Message{MessageID: fmt.Sprintf("target-%d", i), Sender: sender, Recipient: recipient, MessageBox: "target", Body: "x"}
		if ok, err := s.Deliver(msg, "sender"); err != nil || !ok {
			t.Fatal(err)
		}
	}
	examined := 0
	s.onListIterate = func() { examined++ }
	msgs, err := s.List(recipient, "target")
	if err != nil || len(msgs) != 3 || examined != 3 {
		t.Fatalf("list len=%d examined=%d err=%v", len(msgs), examined, err)
	}
}

func TestBoxPrefixIsolation(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient := testIdentity(t), testIdentity(t)
	for i, box := range []string{"x:y", "x:y:z"} {
		msg := &Message{MessageID: fmt.Sprintf("id-%d", i), Sender: sender, Recipient: recipient, MessageBox: box, Body: box}
		if _, err := s.Deliver(msg, "sender"); err != nil {
			t.Fatal(err)
		}
	}
	for _, box := range []string{"x:y", "x:y:z"} {
		msgs, err := s.List(recipient, box)
		if err != nil || len(msgs) != 1 || msgs[0].Body != box {
			t.Fatalf("box %q = %+v, %v", box, msgs, err)
		}
	}
}

func TestArrivalOrderAcrossBigEndianBoundaries(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient := testIdentity(t), testIdentity(t)
	s.seq = 254
	for _, value := range []uint64{255, 256} {
		msg := &Message{MessageID: fmt.Sprint(value), Sender: sender, Recipient: recipient, MessageBox: "box", Body: fmt.Sprint(value)}
		if _, err := s.Deliver(msg, "sender"); err != nil {
			t.Fatal(err)
		}
	}
	s.seq = 65534
	for _, value := range []uint64{65535, 65536} {
		msg := &Message{MessageID: fmt.Sprint(value), Sender: sender, Recipient: recipient, MessageBox: "box", Body: fmt.Sprint(value)}
		if _, err := s.Deliver(msg, "sender"); err != nil {
			t.Fatal(err)
		}
	}
	msgs, err := s.List(recipient, "box")
	if err != nil || len(msgs) != 4 {
		t.Fatalf("list = %d, %v", len(msgs), err)
	}
	for i, want := range []string{"255", "256", "65535", "65536"} {
		if msgs[i].Body != want {
			t.Fatalf("message %d = %q, want %q", i, msgs[i].Body, want)
		}
	}
}

func TestCrossNodeIDsDoNotOverwrite(t *testing.T) {
	a := testStore(t, Options{})
	b := testStore(t, Options{})
	sender, recipient := testIdentity(t), testIdentity(t)
	originA, originB := testIdentity(t), testIdentity(t)
	msgA := &Message{Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "from-a"}
	idA, err := a.Send(msgA, originA)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := b.Deliver(msgA, originA); err != nil || !ok {
		t.Fatalf("deliver A = %v, %v", ok, err)
	}
	msgB := &Message{Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "from-b"}
	idB, err := b.Send(msgB, originB)
	if err != nil {
		t.Fatal(err)
	}
	if idA == idB {
		t.Fatal("node-local sends collided")
	}
	msgs, _ := b.List(recipient, "inbox")
	if len(msgs) != 2 || msgs[0].Body != "from-a" || msgs[1].Body != "from-b" {
		t.Fatalf("messages = %+v", msgs)
	}
}

func TestSequencePersistsAcrossReopen(t *testing.T) {
	path := t.TempDir()
	sender, recipient := testIdentity(t), testIdentity(t)
	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deliver(&Message{MessageID: "first", Sender: sender, Recipient: recipient, MessageBox: "box", Body: "first"}, "sender"); err != nil {
		t.Fatal(err)
	}
	firstSeq := s.seq
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.seq != firstSeq {
		t.Fatalf("reopened sequence = %d, want %d", s.seq, firstSeq)
	}
	if _, err := s.Deliver(&Message{MessageID: "second", Sender: sender, Recipient: recipient, MessageBox: "box", Body: "second"}, "sender"); err != nil {
		t.Fatal(err)
	}
	msgs, _ := s.List(recipient, "box")
	if len(msgs) != 2 || msgs[0].Body != "first" || msgs[1].Body != "second" {
		t.Fatalf("reopened order = %+v", msgs)
	}
}
