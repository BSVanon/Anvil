package messaging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func writeV1Messages(t *testing.T, path, recipient string, count int) {
	t.Helper()
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	batch := new(leveldb.Batch)
	for i := 0; i < count; i++ {
		msg := Message{
			MessageID: fmt.Sprint(i), Sender: "sender", Recipient: recipient,
			MessageBox: "box", Body: "x", Timestamp: int64(i),
		}
		raw, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		batch.Put([]byte("msg:"+recipient+":"+msg.MessageID), raw)
		if (i+1)%1000 == 0 {
			if err := db.Write(batch, nil); err != nil {
				t.Fatal(err)
			}
			batch.Reset()
		}
	}
	if batch.Len() != 0 {
		if err := db.Write(batch, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func countPrefix(t *testing.T, db *leveldb.DB, prefix []byte) int {
	t.Helper()
	count := 0
	iter := db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()
	for iter.Next() {
		count++
	}
	if err := iter.Error(); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestMigrationIndexOrdersSignedTimestampsAndMixedIDs(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []Message{
		{MessageID: "10", Timestamp: -1},
		{MessageID: "2", Timestamp: -1},
		{MessageID: "1x", Timestamp: -1},
		{MessageID: "0", Timestamp: 0},
		{MessageID: "zero-nonnumeric", Timestamp: 0},
	}
	for _, msg := range fixtures {
		msg.Sender, msg.Recipient, msg.MessageBox, msg.Body = "sender", recipient, "box", "x"
		raw, _ := json.Marshal(msg)
		if err := db.Put([]byte("msg:"+recipient+":"+msg.MessageID), raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	msgs, err := s.List(recipient, "box")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2", "10", "1x", "0", "zero-nonnumeric"}
	for i, id := range want {
		if msgs[i].MessageID != id {
			t.Fatalf("order[%d] = %q, want %q", i, msgs[i].MessageID, id)
		}
	}
}

func TestMigrationResumesAfterPartialPassOne(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	writeV1Messages(t, path, recipient, 1500)
	migrationPass1TestHook = func(indexed int) error {
		if indexed == migrationIndexBatchSize {
			return errors.New("simulated pass one crash")
		}
		return nil
	}
	_, err := NewStore(path, Options{})
	migrationPass1TestHook = nil
	if err == nil || err.Error() != "simulated pass one crash" {
		t.Fatalf("first migration error = %v", err)
	}

	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 1500 || countPrefix(t, s.db, prefixV1) != 0 || countPrefix(t, s.db, prefixMigration) != 0 {
		t.Fatalf("resumed migration counts: stored=%d v1=%d mg=%d", s.Count(), countPrefix(t, s.db, prefixV1), countPrefix(t, s.db, prefixMigration))
	}
	checkCounterInvariant(t, s)
}

func TestMigrationDuplicateIndexLeavesV1Record(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	writeV1Messages(t, path, recipient, 1)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(indexKey(recipient, "0"), []byte("stale-primary"), nil); err != nil {
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
	v1Key := []byte("msg:" + recipient + ":0")
	if present, err := s.db.Has(v1Key, nil); err != nil || !present {
		t.Fatalf("duplicate v1 present=%v err=%v", present, err)
	}
	if got := countPrefix(t, s.db, prefixMigration); got != 0 {
		t.Fatalf("migration index keys = %d, want 0", got)
	}
}

func TestMigrationNormalizesValidSender(t *testing.T) {
	path := t.TempDir()
	recipient, sender := testIdentity(t), testIdentity(t)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MessageID: "1", Sender: strings.ToUpper(sender), Recipient: recipient, MessageBox: "box", Body: "x", Timestamp: time.Now().Unix()}
	raw, _ := json.Marshal(msg)
	if err := db.Put([]byte("msg:"+recipient+":1"), raw, nil); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	msgs, err := s.List(recipient, "box")
	if err != nil || len(msgs) != 1 || msgs[0].Sender != sender {
		t.Fatalf("migrated sender = %+v, err=%v", msgs, err)
	}
}

func TestMigrationFiftyThousandRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("large migration")
	}
	path := t.TempDir()
	recipient := testIdentity(t)
	writeV1Messages(t, path, recipient, 50000)
	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Count() != 50000 {
		t.Fatalf("count = %d, want 50000", s.Count())
	}
	if countPrefix(t, s.db, prefixV1) != 0 || countPrefix(t, s.db, prefixMigration) != 0 {
		t.Fatal("migration left v1 or migration-index keys")
	}
}

func TestMigrationPassOneSkipsUnservableRecordsBeforeIndexing(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		message  Message
		servable bool
	}
	fixtures := []fixture{
		{message: Message{MessageID: "normal-1", Body: "one"}, servable: true},
		{message: Message{MessageID: "normal-2", Body: "two"}, servable: true},
		{message: Message{MessageID: strings.Repeat("a", 300), Body: "oversized-id"}},
		{message: Message{MessageID: strings.Repeat("b", 64<<10), Body: "huge-id"}},
		{message: Message{MessageID: "huge-body", Body: strings.Repeat("c", 2<<20)}},
	}
	invalid := make(map[string][]byte)
	for i, item := range fixtures {
		msg := item.message
		msg.Sender, msg.Recipient, msg.MessageBox, msg.Timestamp = "sender", recipient, "box", int64(i+1)
		raw, marshalErr := json.Marshal(msg)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		key := []byte("msg:" + recipient + ":" + msg.MessageID)
		if err := db.Put(key, raw, nil); err != nil {
			t.Fatal(err)
		}
		if !item.servable {
			invalid[string(key)] = append([]byte(nil), raw...)
		}
	}

	s := &Store{db: db, now: time.Now}
	counts := migrationCounts{}
	migrationPass1TestHook = func(_ int) error {
		iter := db.NewIterator(util.BytesPrefix(prefixMigration), nil)
		defer iter.Release()
		for iter.Next() {
			if _, found := invalid[string(iter.Value())]; found {
				t.Error("pass one indexed an unservable v1 record")
			}
		}
		return iter.Error()
	}
	t.Cleanup(func() { migrationPass1TestHook = nil })
	if err := s.buildMigrationIndex(&counts); err != nil {
		t.Fatal(err)
	}
	migrationPass1TestHook = nil
	if counts.unservable != 3 || counts.undecodable != 0 {
		t.Fatalf("pass-one counts = %+v, want unservable=3", counts)
	}
	if got := countPrefix(t, db, prefixMigration); got != 2 {
		t.Fatalf("pass-one migration keys = %d, want 2", got)
	}
	if err := s.moveMigrationIndex(&counts); err != nil {
		t.Fatal(err)
	}
	if counts.inserted != 2 || counts.unservable != 3 || counts.undecodable != 0 {
		t.Fatalf("final migration counts = %+v", counts)
	}
	for key, want := range invalid {
		got, err := db.Get([]byte(key), nil)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("unservable v1 record changed: value bytes=%d want=%d err=%v", len(got), len(want), err)
		}
	}
	if got := countPrefix(t, db, prefixMigration); got != 0 {
		t.Fatalf("migration keys remaining = %d", got)
	}
	msgs, err := s.List(recipient, "box")
	if err != nil || len(msgs) != 2 {
		t.Fatalf("normal migrated messages = %d, %v", len(msgs), err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationPassOneFlushesByAccumulatedBytes(t *testing.T) {
	path := t.TempDir()
	recipient := testIdentity(t)
	writeV1Messages(t, path, recipient, 8)
	previousBytes := migrationIndexBatchBytes
	migrationIndexBatchBytes = 1
	flushes := 0
	migrationPass1TestHook = func(_ int) error {
		flushes++
		return nil
	}
	t.Cleanup(func() {
		migrationIndexBatchBytes = previousBytes
		migrationPass1TestHook = nil
	})
	s, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	migrationPass1TestHook = nil
	if flushes != 8 {
		t.Fatalf("pass-one flushes = %d, want 8", flushes)
	}
	if s.Count() != 8 || countPrefix(t, s.db, prefixV1) != 0 || countPrefix(t, s.db, prefixMigration) != 0 {
		t.Fatalf("migration state: stored=%d v1=%d mg=%d", s.Count(), countPrefix(t, s.db, prefixV1), countPrefix(t, s.db, prefixMigration))
	}
}
