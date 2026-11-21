package messaging

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

func TestVersion340MessageboxV2ReopensWithoutRewrite(t *testing.T) {
	path := t.TempDir()
	recipient, sender := testIdentity(t), testIdentity(t)
	primary := primaryKey(recipient, "inbox", 1)
	legacy := struct {
		Message
		AttestedBy string `json:"senderAttestedBy"`
		ReceivedAt int64  `json:"receivedAt"`
	}{
		Message:    Message{MessageID: "legacy-v2", Sender: sender, Recipient: recipient, MessageBox: "inbox", Body: "preserve me", Timestamp: 1700000000},
		AttestedBy: "local",
		ReceivedAt: 1700000001,
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := new(leveldb.Batch)
	batch.Put(keyMetaSchema, []byte("2"))
	putUint64(batch, keyMetaSeq, 1)
	batch.Put(primary, raw)
	batch.Put(indexKey(recipient, legacy.MessageID), primary)
	batch.Put(expiryKey(legacy.ReceivedAt, primary), nil)
	if err := db.Write(batch, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := snapshotMessagebox(t, path)

	store, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	messages, err := store.List(recipient, "inbox")
	if err != nil || len(messages) != 1 || messages[0].Body != legacy.Body || messages[0].ExpiryBase != 0 {
		t.Fatalf("reopened v2 message = %+v, %v", messages, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	after := snapshotMessagebox(t, path)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("v2 logical records changed on reopen\nbefore=%q\nafter=%q", before, after)
	}
}

func snapshotMessagebox(t *testing.T, path string) map[string]string {
	t.Helper()
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got := make(map[string]string)
	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		got[string(iter.Key())] = string(iter.Value())
	}
	if err := iter.Error(); err != nil {
		t.Fatal(err)
	}
	return got
}
