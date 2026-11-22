package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
)

func TestReleasePageEvictsDistinctPersistedTombstones(t *testing.T) {
	const pageSize = 200
	now := time.Unix(2_000_000_000, 0)
	path := t.TempDir()
	store, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: pageSize, MaxTTL: 3600, Now: func() time.Time { return now },
	})
	seed := new(leveldb.Batch)
	oldestMember := fmt.Sprintf("02%064x", 1)
	for i := 0; i < pageSize; i++ {
		issuedAt := now.UnixMilli()
		if i == 0 {
			issuedAt = now.Add(-time.Second).UnixMilli()
		}
		record := PrivateHomeRecord{
			Kind: PrivateHomeRelease, Member: fmt.Sprintf("02%064x", i+1), Homes: []string{},
			IssuedAt: issuedAt, Signature: "persisted",
		}
		raw, _ := json.Marshal(record)
		seed.Put(privateHomeRecordKey(record.Member), raw)
	}
	if err := store.db.Write(seed, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Records(); err != nil {
		t.Fatal(err)
	}
	oldest, exists, err := registry.recordLocked(oldestMember)
	if err != nil || !exists {
		t.Fatalf("oldest tombstone = %+v, %v, %v", oldest, exists, err)
	}
	duplicate := privateHomeExpiry{at: registry.recordExpiry(oldest), member: oldestMember, kind: privateHomeExpiryRecord}
	for i := 0; i < pageSize; i++ {
		pushPrivateHomeExpiry(&registry.ordinaryExpiries, duplicate)
	}

	records := make([]PrivateHomeRecord, pageSize)
	for i := range records {
		member := privateHomeKey(t)
		records[i] = signPrivateHome(t, member, PrivateHomeRecord{
			Kind: PrivateHomeRelease, Member: privateHomeKeyHex(member), Homes: []string{},
			IssuedAt: now.Add(time.Duration(i+1) * time.Millisecond).UnixMilli(),
		})
	}
	for i, result := range registry.ApplyBatch(context.Background(), records) {
		if result != nil {
			t.Fatalf("release %d: %v", i, result)
		}
	}
	if registry.ordinaryTombstones != pageSize || countPrivateHomeRows(t, store) != pageSize {
		t.Fatalf("before reopen: cached=%d persisted=%d", registry.ordinaryTombstones, countPrivateHomeRows(t, store))
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry = NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: pageSize, MaxTTL: 3600, Now: func() time.Time { return now },
	})
	if _, err := registry.Records(); err != nil {
		t.Fatal(err)
	}
	persisted := countPrivateHomeRows(t, store)
	if persisted > pageSize || registry.ordinaryTombstones != persisted {
		t.Fatalf("after reopen: cached=%d persisted=%d cap=%d", registry.ordinaryTombstones, persisted, pageSize)
	}
}
