package messaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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

func TestMigrationPassOneRecordContainsOnlyMetadata(t *testing.T) {
	typ := reflect.TypeOf(v1Record{})
	want := []string{"key", "timestamp", "messageID", "recipient"}
	wantTypes := []reflect.Type{
		reflect.TypeOf([]byte(nil)), reflect.TypeOf(int64(0)),
		reflect.TypeOf(""), reflect.TypeOf(""),
	}
	if typ.NumField() != len(want) {
		t.Fatalf("v1Record has %d fields, want metadata fields %v", typ.NumField(), want)
	}
	for i, name := range want {
		field := typ.Field(i)
		if field.Name != name || field.Type != wantTypes[i] {
			t.Fatalf("v1Record field %d = %s %v, want %s %v", i, field.Name, field.Type, name, wantTypes[i])
		}
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
