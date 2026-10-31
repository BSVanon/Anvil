package messaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func writeV1Fixture(t *testing.T, path, recipient string) {
	t.Helper()
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	records := []Message{
		{MessageID: "1000000", Sender: "sender", Recipient: strings.ToUpper(recipient), MessageBox: "box", Body: "million", Timestamp: 20},
		{MessageID: "999999", Sender: "sender", Recipient: strings.ToUpper(recipient), MessageBox: "box", Body: "before-million", Timestamp: 20},
		{MessageID: "alpha", Sender: "sender", Recipient: strings.ToUpper(recipient), MessageBox: "box", Body: "first", Timestamp: 10},
		{MessageID: "invalid", Sender: "sender", Recipient: "not-a-public-key", MessageBox: strings.Repeat("b", 129), Body: "kept", Timestamp: 30},
	}
	for _, msg := range records {
		raw, _ := json.Marshal(msg)
		key := []byte("msg:" + msg.Recipient + ":" + msg.MessageID)
		if err := db.Put(key, raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationOrderingIdempotenceAndDataPreservation(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	writeV1Fixture(t, path, recipient)
	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := s.List(recipient, "box")
	if err != nil || len(msgs) != 3 {
		t.Fatalf("list = %d, %v", len(msgs), err)
	}
	for i, want := range []string{"alpha", "999999", "1000000"} {
		if msgs[i].MessageID != want || msgs[i].AttestedBy != "unknown" {
			t.Fatalf("message %d = %+v, want %s/unknown", i, msgs[i], want)
		}
	}
	if s.Count() != 3 {
		t.Fatalf("servable migrated record count = %d, want 3", s.Count())
	}
	checkCounterInvariant(t, s)
	if raw, err := s.db.Get(keyMetaSchema, nil); err != nil || string(raw) != "2" {
		t.Fatalf("schema = %q, %v", raw, err)
	}
	iter := s.db.NewIterator(util.BytesPrefix(prefixV1), nil)
	if !iter.Next() || string(iter.Key()) != "msg:not-a-public-key:invalid" {
		t.Fatalf("unservable v1 key = %q, want invalid record left in place", iter.Key())
	}
	iter.Release()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 3 {
		t.Fatalf("idempotent reopen count = %d", s.Count())
	}
	checkCounterInvariant(t, s)
}

func TestMigrationRecoversAfterInterruptedInsert(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	writeV1Fixture(t, path, recipient)
	migrationTestHook = func(inserted int) error {
		if inserted == 2 {
			return errors.New("simulated migration crash")
		}
		return nil
	}
	_, err := NewStore(path, Options{})
	migrationTestHook = nil
	if err == nil || err.Error() != "simulated migration crash" {
		t.Fatalf("first migration error = %v", err)
	}
	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 3 {
		t.Fatalf("recovered count = %d", s.Count())
	}
	if got := countPrefix(t, s.db, prefixPrimary); got != 3 {
		t.Fatalf("recovered primary records = %d, want 3", got)
	}
	if got := countPrefix(t, s.db, prefixMigration); got != 0 {
		t.Fatalf("recovered migration index records = %d, want 0", got)
	}
	checkCounterInvariant(t, s)
	for _, id := range []string{"alpha", "999999", "1000000"} {
		var found bool
		iter := s.db.NewIterator(util.BytesPrefix(prefixPrimary), nil)
		for iter.Next() {
			record, decodeErr := decodeRecord(iter.Value())
			if decodeErr == nil && record.MessageID == id {
				found = true
			}
		}
		iter.Release()
		if !found {
			t.Error(fmt.Sprintf("missing recovered message %s", id))
		}
	}
}

func TestMigrationLeavesUndecodableV1RecordAndSucceeds(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	writeV1Fixture(t, path, recipient)
	badKey := []byte("msg:" + recipient + ":broken")
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(badKey, []byte(`{"messageId":`), nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 3 {
		t.Fatalf("good records migrated = %d, want 3", s.Count())
	}
	if raw, err := s.db.Get(badKey, nil); err != nil || string(raw) != `{"messageId":` {
		t.Fatalf("bad v1 record = %q, %v", raw, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 3 {
		t.Fatalf("second open count = %d, want 3", s.Count())
	}
	if ok, err := s.db.Has(badKey, nil); err != nil || !ok {
		t.Fatalf("bad v1 record missing after second open: present=%v err=%v", ok, err)
	}
}

func TestMigrationLeavesControlCharacterBoxUnservable(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	msg := Message{
		MessageID: "control-box", Sender: "sender", Recipient: recipient,
		MessageBox: "inbox\nforged", Body: "body", Timestamp: 30,
	}
	raw, _ := json.Marshal(msg)
	key := []byte("msg:" + recipient + ":" + msg.MessageID)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(key, raw, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 0 {
		t.Fatalf("unservable record count = %d", s.Count())
	}
	if present, err := s.db.Has(key, nil); err != nil || !present {
		t.Fatalf("control-box v1 record present=%v err=%v", present, err)
	}
}

func TestMigrationLeavesUnservableIDsAndBodiesInV1(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	validID := strings.Repeat("x", MaxMessageIDBytes)
	fixtures := []struct {
		message Message
		valid   bool
	}{
		{message: Message{MessageID: strings.Repeat("x", MaxMessageIDBytes+1), Body: "body"}},
		{message: Message{MessageID: "has space", Body: "body"}},
		{message: Message{MessageID: "has\x01control", Body: "body"}},
		{message: Message{MessageID: "empty-body", Body: ""}},
		{message: Message{MessageID: "large-body", Body: strings.Repeat("x", MaxMessageBodyBytes+1)}},
		{message: Message{MessageID: validID, Body: strings.Repeat("x", MaxMessageBodyBytes)}, valid: true},
	}
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	invalidKeys := make([][]byte, 0, len(fixtures)-1)
	for _, fixture := range fixtures {
		msg := fixture.message
		msg.Sender, msg.Recipient, msg.MessageBox, msg.Timestamp = "sender", recipient, "box", 1
		raw, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		key := []byte("msg:" + recipient + ":" + msg.MessageID)
		if err := db.Put(key, raw, nil); err != nil {
			t.Fatal(err)
		}
		if !fixture.valid {
			invalidKeys = append(invalidKeys, key)
		}
	}

	s := &Store{db: db, now: time.Now}
	counts := migrationCounts{}
	if err := s.buildMigrationIndex(&counts); err != nil {
		t.Fatal(err)
	}
	if err := s.moveMigrationIndex(&counts); err != nil {
		t.Fatal(err)
	}
	if counts.inserted != 1 || counts.unservable != 5 || counts.undecodable != 0 || counts.duplicate != 0 {
		t.Fatalf("migration counts = %+v, want inserted=1 unservable=5", counts)
	}
	if got := countPrefix(t, db, prefixV1); got != 5 {
		t.Fatalf("v1 keys remaining = %d, want 5", got)
	}
	for _, key := range invalidKeys {
		if present, err := db.Has(key, nil); err != nil || !present {
			t.Fatalf("unservable v1 key %q present=%v err=%v", key, present, err)
		}
	}
	if got := countPrefix(t, db, prefixMigration); got != 0 {
		t.Fatalf("migration index keys remaining = %d, want 0", got)
	}
	msgs, err := s.List(recipient, "box")
	if err != nil || len(msgs) != 1 || msgs[0].MessageID != validID || len(msgs[0].Body) != MaxMessageBodyBytes {
		bodyBytes := 0
		if len(msgs) == 1 {
			bodyBytes = len(msgs[0].Body)
		}
		t.Fatalf("migrated message count=%d bodyBytes=%d err=%v", len(msgs), bodyBytes, err)
	}
	if deleted, err := s.Acknowledge(recipient, []string{validID}); err != nil || deleted != 1 {
		t.Fatalf("acknowledge migrated message = %d, %v", deleted, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationClampsNonPositiveTimestampToNow(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, timestamp := range []int64{0, -100} {
		msg := Message{
			MessageID: fmt.Sprint(i), Sender: "sender", Recipient: recipient,
			MessageBox: "box", Body: "body", Timestamp: timestamp,
		}
		raw, _ := json.Marshal(msg)
		if err := db.Put([]byte("msg:"+recipient+":"+msg.MessageID), raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path, Options{TTLSeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	msgs, err := s.List(recipient, "box")
	if err != nil || len(msgs) != 2 {
		t.Fatalf("list = %d, %v", len(msgs), err)
	}
	latest := int64(0)
	for _, msg := range msgs {
		if msg.ReceivedAt <= 0 {
			t.Fatalf("receivedAt was not clamped: %+v", msg)
		}
		if msg.ReceivedAt > latest {
			latest = msg.ReceivedAt
		}
	}
	s.now = func() time.Time { return time.Unix(latest+11, 0) }
	if expired := s.ExpireOld(); expired != 2 {
		t.Fatalf("expired = %d, want 2", expired)
	}
}
