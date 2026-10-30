package messaging

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func TestQuotaScopes(t *testing.T) {
	sender := testIdentity(t)
	recipientA, recipientB := testIdentity(t), testIdentity(t)
	t.Run("pair", func(t *testing.T) {
		s := testStore(t, Options{MaxPairMessages: 1, MaxStoreMessages: 10})
		one := &Message{MessageID: "1", Sender: sender, Recipient: recipientA, MessageBox: "box", Body: "x"}
		two := &Message{MessageID: "2", Sender: sender, Recipient: recipientA, MessageBox: "box", Body: "x"}
		if _, err := s.Deliver(one, "sender"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Deliver(two, "sender"); !errors.Is(err, ErrPairQuota) {
			t.Fatalf("pair error = %v", err)
		}
		two.Recipient = recipientB
		if ok, err := s.Deliver(two, "sender"); err != nil || !ok {
			t.Fatalf("other pair = %v, %v", ok, err)
		}
	})
	t.Run("node", func(t *testing.T) {
		s := testStore(t, Options{MaxPairMessages: 10, MaxStoreMessages: 1})
		for i, recipient := range []string{recipientA, recipientB} {
			_, err := s.Deliver(&Message{MessageID: fmt.Sprint(i), Sender: sender, Recipient: recipient, MessageBox: "box", Body: "x"}, "sender")
			if i == 0 && err != nil {
				t.Fatal(err)
			}
			if i == 1 && !errors.Is(err, ErrStoreFull) {
				t.Fatalf("node error = %v", err)
			}
		}
	})
	t.Run("inbox off then on", func(t *testing.T) {
		s := testStore(t, Options{MaxPairMessages: 10, MaxStoreMessages: 10})
		for i := 0; i < 2; i++ {
			msg := &Message{MessageID: fmt.Sprint(i), Sender: testIdentity(t), Recipient: recipientA, MessageBox: "box", Body: "x"}
			if _, err := s.Deliver(msg, "sender"); err != nil {
				t.Fatalf("disabled inbox quota: %v", err)
			}
		}
		s2 := testStore(t, Options{MaxPairMessages: 10, MaxStoreMessages: 10, MaxInboxMessages: 1})
		if _, err := s2.Deliver(&Message{MessageID: "a", Sender: sender, Recipient: recipientA, MessageBox: "box", Body: "x"}, "sender"); err != nil {
			t.Fatal(err)
		}
		_, err := s2.Deliver(&Message{MessageID: "b", Sender: testIdentity(t), Recipient: recipientA, MessageBox: "box", Body: "x"}, "sender")
		if !errors.Is(err, ErrInboxQuota) {
			t.Fatalf("inbox error = %v", err)
		}
	})
}

func checkCounterInvariant(t *testing.T, s *Store) {
	t.Helper()
	wantNode := counter{}
	wantPair := make(map[string]counter)
	wantInbox := make(map[string]counter)
	iter := s.db.NewIterator(util.BytesPrefix(prefixPrimary), nil)
	for iter.Next() {
		record, err := decodeRecord(iter.Value())
		if err != nil {
			t.Fatal(err)
		}
		bodyBytes := int64(len(record.Body))
		wantNode.Count++
		wantNode.Bytes += bodyBytes
		pairKey := string(pairCounterKey(record.Sender, record.Recipient))
		pair := wantPair[pairKey]
		pair.Count++
		pair.Bytes += bodyBytes
		wantPair[pairKey] = pair
		inboxKey := string(inboxCounterKey(record.Recipient))
		inbox := wantInbox[inboxKey]
		inbox.Count++
		inbox.Bytes += bodyBytes
		wantInbox[inboxKey] = inbox
		primary := append([]byte(nil), iter.Key()...)
		if ok, _ := s.db.Has(indexKey(record.Recipient, record.MessageID), nil); !ok {
			t.Fatalf("missing ID index for %s", record.MessageID)
		}
		if ok, _ := s.db.Has(expiryKey(record.ReceivedAt, primary), nil); !ok {
			t.Fatalf("missing expiry index for %s", record.MessageID)
		}
	}
	iter.Release()
	gotNode, err := readCounter(s.db, keyNodeCounter)
	if err != nil || gotNode != wantNode {
		t.Fatalf("node counter = %+v, want %+v, err=%v", gotNode, wantNode, err)
	}
	for key, want := range wantPair {
		got, err := readCounter(s.db, []byte(key))
		if err != nil || got != want {
			t.Fatalf("pair counter = %+v, want %+v, err=%v", got, want, err)
		}
	}
	for key, want := range wantInbox {
		got, err := readCounter(s.db, []byte(key))
		if err != nil || got != want {
			t.Fatalf("inbox counter = %+v, want %+v, err=%v", got, want, err)
		}
	}
}

func TestCountersRemainConsistent(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 10, MaxPairMessages: 10, MaxStoreMessages: 10})
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	sender, recipient, origin := testIdentity(t), testIdentity(t), testIdentity(t)
	id := sendTest(t, s, sender, recipient, origin, "box", "one")
	if _, err := s.Deliver(&Message{MessageID: "legacy", Sender: sender, Recipient: recipient, MessageBox: "box", Body: "twenty", Timestamp: now.Unix()}, "sender"); err != nil {
		t.Fatal(err)
	}
	checkCounterInvariant(t, s)
	if _, err := s.Acknowledge(recipient, []string{id}); err != nil {
		t.Fatal(err)
	}
	checkCounterInvariant(t, s)
	now = now.Add(11 * time.Second)
	if s.ExpireOld() != 1 {
		t.Fatal("expected one expiry")
	}
	checkCounterInvariant(t, s)
}

func TestAcknowledgeRemovesEmptyPairAndInboxCounters(t *testing.T) {
	s := testStore(t, Options{})
	sender, recipient := testIdentity(t), testIdentity(t)
	ids := make([]string, 0, 2)
	for _, id := range []string{"1", "2"} {
		if ok, err := s.Deliver(&Message{
			MessageID: id, Sender: sender, Recipient: recipient, MessageBox: "box", Body: "body",
		}, "sender"); err != nil || !ok {
			t.Fatalf("deliver %s = %v, %v", id, ok, err)
		}
		ids = append(ids, id)
	}
	if deleted, err := s.Acknowledge(recipient, ids); err != nil || deleted != 2 {
		t.Fatalf("acknowledge = %d, %v", deleted, err)
	}
	for name, key := range map[string][]byte{
		"pair": pairCounterKey(sender, recipient), "inbox": inboxCounterKey(recipient),
	} {
		if ok, err := s.db.Has(key, nil); err != nil || ok {
			t.Fatalf("%s counter present=%v err=%v", name, ok, err)
		}
	}
	if node, err := readCounter(s.db, keyNodeCounter); err != nil || node != (counter{}) {
		t.Fatalf("node counter = %+v, %v", node, err)
	}
	if ok, err := s.db.Has(keyNodeCounter, nil); err != nil || !ok {
		t.Fatalf("node counter present=%v err=%v", ok, err)
	}
}

func TestExpireOldProcessesMoreThanTwoChunks(t *testing.T) {
	s := testStore(t, Options{TTLSeconds: 10, MaxPairMessages: 30000, MaxStoreMessages: 30000})
	sender, recipient := testIdentity(t), testIdentity(t)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	seedExpiredMessages(t, s, sender, recipient, 25000, now.Unix())
	now = now.Add(11 * time.Second)
	keys, _ := s.expiredKeys(now.Unix()-s.opts.TTLSeconds, expiryChunkSize)
	if len(keys) != expiryChunkSize {
		t.Fatalf("first expiry chunk = %d, want %d", len(keys), expiryChunkSize)
	}
	if expired := s.ExpireOld(); expired != 25000 {
		t.Fatalf("expired = %d, want 25000", expired)
	}
	if s.Count() != 0 {
		t.Fatalf("count after expiry = %d", s.Count())
	}
	checkCounterInvariant(t, s)
	for name, key := range map[string][]byte{
		"pair": pairCounterKey(sender, recipient), "inbox": inboxCounterKey(recipient),
	} {
		if ok, err := s.db.Has(key, nil); err != nil || ok {
			t.Fatalf("%s counter present=%v err=%v", name, ok, err)
		}
	}
	for name, prefix := range map[string][]byte{
		"message": prefixPrimary, "index": prefixIndex, "expiry": prefixExpiry,
	} {
		iter := s.db.NewIterator(util.BytesPrefix(prefix), nil)
		if iter.Next() {
			t.Errorf("%s key remains: %q", name, iter.Key())
		}
		iter.Release()
	}
}

func seedExpiredMessages(t *testing.T, s *Store, sender, recipient string, count int, receivedAt int64) {
	t.Helper()
	batch := new(leveldb.Batch)
	for i := 1; i <= count; i++ {
		record := &StoredMessage{
			Message: Message{
				MessageID: fmt.Sprint(i), Sender: sender, Recipient: recipient,
				MessageBox: "box", Body: "x", Timestamp: receivedAt,
			},
			AttestedBy: "sender", ReceivedAt: receivedAt,
		}
		data, err := encodeRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		primary := primaryKey(recipient, "box", uint64(i))
		batch.Put(primary, data)
		batch.Put(indexKey(recipient, record.MessageID), primary)
		batch.Put(expiryKey(receivedAt, primary), nil)
	}
	value := counter{Count: int64(count), Bytes: int64(count)}
	if err := putCounter(batch, pairCounterKey(sender, recipient), value); err != nil {
		t.Fatal(err)
	}
	if err := putCounter(batch, inboxCounterKey(recipient), value); err != nil {
		t.Fatal(err)
	}
	if err := putCounter(batch, keyNodeCounter, value); err != nil {
		t.Fatal(err)
	}
	putUint64(batch, keyMetaSeq, uint64(count))
	if err := s.db.Write(batch, nil); err != nil {
		t.Fatal(err)
	}
	s.seq = uint64(count)
}
