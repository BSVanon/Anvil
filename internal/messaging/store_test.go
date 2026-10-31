package messaging

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func testIdentity(t *testing.T) string {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(strings.TrimSpace(fmtHex(key.PubKey().Compressed())))
}

func fmtHex(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, value := range raw {
		out[i*2] = digits[value>>4]
		out[i*2+1] = digits[value&15]
	}
	return string(out)
}

func testStore(t *testing.T, opts Options) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sendTest(t *testing.T, s *Store, sender, recipient, origin, box, body string) string {
	t.Helper()
	id, err := s.Send(&Message{Sender: sender, Recipient: recipient, MessageBox: box, Body: body}, origin)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSendListAcknowledgeAndEmptyArray(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 3600})
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	id1 := sendTest(t, s, sender, strings.ToUpper(recipient), origin, "inbox", "first")
	id2 := sendTest(t, s, sender, recipient, origin, "inbox", "second")

	msgs, err := s.List(strings.ToUpper(recipient), "inbox")
	if err != nil || len(msgs) != 2 {
		t.Fatalf("list = %d, %v", len(msgs), err)
	}
	if msgs[0].MessageID != id1 || msgs[1].MessageID != id2 {
		t.Fatalf("arrival order = %q, %q", msgs[0].MessageID, msgs[1].MessageID)
	}
	if msgs[0].AttestedBy != "local" || msgs[0].ReceivedAt == 0 {
		t.Fatalf("stored metadata = %+v", msgs[0])
	}
	if n, err := s.Acknowledge(strings.ToUpper(recipient), []string{id1}); err != nil || n != 1 {
		t.Fatalf("ack = %d, %v", n, err)
	}
	msgs, _ = s.List(recipient, "inbox")
	if len(msgs) != 1 || msgs[0].MessageID != id2 {
		t.Fatalf("after ack = %+v", msgs)
	}
	if _, err := s.Acknowledge(testIdentity(t), []string{id2}); err != nil {
		t.Fatal(err)
	}

	empty, err := s.List(recipient, "missing")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(empty)
	if string(raw) != "[]" {
		t.Fatalf("empty list JSON = %s", raw)
	}
}

func TestSendValidationAndMessageID(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	id := sendTest(t, s, sender, recipient, origin, "inbox", "hello")
	if !IsV2MessageID(id) || !VerifyMessageID(&Message{
		MessageID: id, Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "hello",
		Timestamp: func() int64 { msgs, _ := s.List(recipient, "inbox"); return msgs[0].Timestamp }(),
	}, origin) {
		t.Fatalf("invalid generated v2 ID %q", id)
	}
	for _, tc := range []struct {
		msg  Message
		want error
	}{
		{Message{Sender: sender, Recipient: "02bad", MessageBox: "x", Body: "x"}, ErrInvalidRecipient},
		{Message{Sender: sender, Recipient: recipient, Body: "x"}, ErrInvalidMessageBox},
		{Message{Sender: sender, Recipient: recipient, MessageBox: strings.Repeat("x", 129), Body: "x"}, ErrMessageBoxTooLarge},
		{Message{Sender: sender, Recipient: recipient, MessageBox: "x"}, ErrInvalidMessageBody},
		{Message{Sender: sender, Recipient: recipient, MessageBox: "x", Body: strings.Repeat("x", MaxMessageBodyBytes+1)}, ErrMessageBodyTooLarge},
	} {
		if _, err := s.Send(&tc.msg, origin); err != tc.want {
			t.Errorf("Send error = %v, want %v", err, tc.want)
		}
	}
}

func TestExpiryUsesReceivedAtNotFutureTimestamp(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 10})
	sender, recipient := testIdentity(t), testIdentity(t)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	msg := &Message{MessageID: "legacy-1", Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "future", Timestamp: now.Add(365 * 24 * time.Hour).Unix()}
	if ok, err := s.Deliver(msg, "sender"); err != nil || !ok {
		t.Fatalf("deliver = %v, %v", ok, err)
	}
	now = now.Add(11 * time.Second)
	if expired := s.ExpireOld(); expired != 1 {
		t.Fatalf("expired = %d", expired)
	}
	if s.Count() != 0 {
		t.Fatalf("count = %d", s.Count())
	}
}

func TestDeliverRejectsInvalidSenderAndMessageID(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient := testIdentity(t), testIdentity(t)
	base := Message{
		MessageID: "1000000", Sender: sender, Recipient: recipient,
		MessageBox: "inbox", Body: "body", Timestamp: 1_700_000_000,
	}
	for name, mutate := range map[string]func(*Message){
		"sender":   func(msg *Message) { msg.Sender = "not-a-key" },
		"too long": func(msg *Message) { msg.MessageID = strings.Repeat("x", 129) },
		"space":    func(msg *Message) { msg.MessageID = "bad id" },
		"control":  func(msg *Message) { msg.MessageID = "bad\x1fid" },
	} {
		t.Run(name, func(t *testing.T) {
			msg := base
			mutate(&msg)
			_, err := s.Deliver(&msg, "sender")
			want := ErrInvalidMessageID
			if name == "sender" {
				want = ErrInvalidSender
			}
			if !errors.Is(err, want) {
				t.Fatalf("Deliver error = %v, want %v", err, want)
			}
		})
	}

	if ok, err := s.Deliver(&base, "sender"); err != nil || !ok {
		t.Fatalf("legacy decimal ID = %v, %v", ok, err)
	}
	v2 := base
	v2.Body = "v2"
	origin := testIdentity(t)
	id, err := NewMessageID(&v2, origin)
	if err != nil {
		t.Fatal(err)
	}
	v2.MessageID = id
	if ok, err := s.Deliver(&v2, origin); err != nil || !ok {
		t.Fatalf("v2 ID = %v, %v", ok, err)
	}
}

func TestSenderCaseVariantsSharePairQuota(t *testing.T) {
	sender, recipient := testIdentity(t), testIdentity(t)

	t.Run("deliver", func(t *testing.T) {
		s := testStore(t, Options{MaxPairMessages: 1, MaxStoreMessages: 10})
		first := &Message{MessageID: "upper", Sender: strings.ToUpper(sender), Recipient: recipient, MessageBox: "box", Body: "one"}
		if inserted, err := s.Deliver(first, "sender"); err != nil || !inserted {
			t.Fatalf("first deliver = %v, %v", inserted, err)
		}
		second := &Message{MessageID: "lower", Sender: sender, Recipient: recipient, MessageBox: "box", Body: "two"}
		if _, err := s.Deliver(second, "sender"); !errors.Is(err, ErrPairQuota) {
			t.Fatalf("second deliver error = %v, want pair quota", err)
		}
		msgs, _ := s.List(recipient, "box")
		if len(msgs) != 1 || msgs[0].Sender != sender {
			t.Fatalf("stored sender = %+v, want lowercase", msgs)
		}
	})

	t.Run("send", func(t *testing.T) {
		s := testStore(t, Options{MaxPairMessages: 1, MaxStoreMessages: 10})
		origin := testIdentity(t)
		upper := &Message{Sender: strings.ToUpper(sender), Recipient: recipient, MessageBox: "box", Body: "one"}
		if _, err := s.Send(upper, origin); err != nil {
			t.Fatal(err)
		}
		if upper.Sender != sender {
			t.Fatalf("send sender = %q, want %q", upper.Sender, sender)
		}
		lower := &Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "two"}
		if _, err := s.Send(lower, origin); !errors.Is(err, ErrPairQuota) {
			t.Fatalf("second send error = %v, want pair quota", err)
		}
	})
}

func TestInsertClampsNonPositiveReceivedAt(t *testing.T) {
	s := testStore(t, Options{})
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	record := &StoredMessage{
		Message: Message{
			MessageID: "1", Sender: testIdentity(t), Recipient: testIdentity(t),
			MessageBox: "box", Body: "body",
		},
		AttestedBy: "sender", ReceivedAt: -1,
	}
	if err := s.insert(record, false); err != nil {
		t.Fatal(err)
	}
	msgs, err := s.List(record.Recipient, record.MessageBox)
	if err != nil || len(msgs) != 1 || msgs[0].ReceivedAt != now.Unix() {
		t.Fatalf("stored messages = %+v, %v", msgs, err)
	}
}
