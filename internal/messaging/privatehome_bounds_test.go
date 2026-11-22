package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func applyUncheckedPrivateHomeRecord(t *testing.T, registry *PrivateHomeStore, record PrivateHomeRecord) {
	t.Helper()
	registry.messages.writeMu.Lock()
	defer registry.messages.writeMu.Unlock()
	if err := registry.prepareLocked(); err != nil {
		t.Fatal(err)
	}
	batch := new(leveldb.Batch)
	if err := registry.applySignedLocked(record, nil, batch, nil); err != nil {
		t.Fatal(err)
	}
	if err := registry.messages.db.Write(batch, nil); err != nil {
		t.Fatal(err)
	}
	if err := registry.compactExpiryHeapsLocked(); err != nil {
		t.Fatal(err)
	}
}

func countPrivateHomeRows(t *testing.T, store *Store) int {
	t.Helper()
	iter := store.db.NewIterator(util.BytesPrefix(privateHomeRecordPrefix), nil)
	defer iter.Release()
	count := 0
	for iter.Next() {
		count++
	}
	if err := iter.Error(); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestPrivateHomeExpiryIndexesStayProportionalAcrossRenewalsAndRestart(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	path := t.TempDir()
	store, err := NewStore(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	home := privateHomeKeyHex(privateHomeKey(t))
	memberKey := privateHomeKey(t)
	member := privateHomeKeyHex(memberKey)
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: 4, MaxTTL: 3600, AllowedHomes: []string{home}, Now: func() time.Time { return now },
	})
	base := now.UnixMilli()
	claim := signPrivateHome(t, memberKey, PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: member, Homes: []string{home}, IssuedAt: base,
		ExpiresAt: now.Add(30 * time.Minute).Unix(),
	})
	if err := registry.Apply(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 10_000; i++ {
		claim.IssuedAt = base + i
		applyUncheckedPrivateHomeRecord(t, registry, claim)
	}
	if got, limit := registry.expirations.Len(), 2*(registry.primaryRecords+registry.revocations)+64; got > limit {
		t.Fatalf("claim expiry heap = %d, limit %d", got, limit)
	}

	release := PrivateHomeRecord{
		Kind: PrivateHomeRelease, Member: member, Homes: []string{}, IssuedAt: base + 10_001, Signature: "signed",
	}
	for i := int64(0); i < 10_000; i++ {
		release.IssuedAt = base + 10_001 + i
		applyUncheckedPrivateHomeRecord(t, registry, release)
	}
	if got, limit := registry.ordinaryExpiries.Len(), 2*registry.ordinaryTombstones+64; got > limit {
		t.Fatalf("release expiry heap = %d, limit %d", got, limit)
	}

	cutoff := release.IssuedAt + 1
	for i := int64(0); i < 10_000; i++ {
		if _, err := registry.ApplyRevocation(member, cutoff+i); err != nil {
			t.Fatal(err)
		}
	}
	if got, limit := registry.expirations.Len(), 2*(registry.primaryRecords+registry.revocations)+64; got > limit {
		t.Fatalf("trusted tombstone expiry heap = %d, limit %d", got, limit)
	}
	recordsBefore, err := registry.Records()
	if err != nil {
		t.Fatal(err)
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
		MaxMembers: 4, MaxTTL: 3600, AllowedHomes: []string{home}, Now: func() time.Time { return now },
	})
	recordsAfter, err := registry.Records()
	if err != nil || len(recordsAfter) != len(recordsBefore) || recordsAfter[0].IssuedAt != recordsBefore[0].IssuedAt {
		t.Fatalf("records after restart = %+v, error %v; before %+v", recordsAfter, err, recordsBefore)
	}
	if registry.expirations.Len() > 2*(registry.primaryRecords+registry.revocations)+64 ||
		registry.ordinaryExpiries.Len() > 2*registry.ordinaryTombstones+64 {
		t.Fatal("restart rebuilt an oversized expiry heap")
	}
}

func TestPrivateHomeExpiryNeverDeletesANewerRecord(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	home := privateHomeKeyHex(privateHomeKey(t))
	memberKey := privateHomeKey(t)
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: 2, MaxTTL: 3600, AllowedHomes: []string{home}, Now: func() time.Time { return now },
	})
	old := signPrivateHome(t, memberKey, PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: privateHomeKeyHex(memberKey), Homes: []string{home},
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(10 * time.Second).Unix(),
	})
	if err := registry.Apply(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	newer := old
	newer.IssuedAt++
	newer.ExpiresAt = now.Add(20 * time.Second).Unix()
	applyUncheckedPrivateHomeRecord(t, registry, newer)
	now = now.Add(10 * time.Second)
	if got, ok, err := registry.Current(old.Member); err != nil || !ok || got.IssuedAt != newer.IssuedAt {
		t.Fatalf("newer claim at old deadline = %+v, %v, %v", got, ok, err)
	}
	now = now.Add(10 * time.Second)
	if _, ok, err := registry.Current(old.Member); err != nil || ok {
		t.Fatalf("claim at current deadline: current=%v error=%v", ok, err)
	}
}

func TestReleaseAndTrustedCutoffExpiryUseTheCurrentDeadline(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: 2, MaxTTL: 3600, Now: func() time.Time { return now },
	})
	releaseKey := privateHomeKey(t)
	oldRelease := signPrivateHome(t, releaseKey, PrivateHomeRecord{
		Kind: PrivateHomeRelease, Member: privateHomeKeyHex(releaseKey), Homes: []string{}, IssuedAt: now.UnixMilli(),
	})
	if err := registry.Apply(context.Background(), oldRelease); err != nil {
		t.Fatal(err)
	}
	newRelease := signPrivateHome(t, releaseKey, PrivateHomeRecord{
		Kind: PrivateHomeRelease, Member: oldRelease.Member, Homes: []string{}, IssuedAt: oldRelease.IssuedAt + 1000,
	})
	if err := registry.Apply(context.Background(), newRelease); err != nil {
		t.Fatal(err)
	}
	revokedMember := privateHomeKeyHex(privateHomeKey(t))
	oldCutoff := now.UnixMilli()
	if _, err := registry.ApplyRevocation(revokedMember, oldCutoff); err != nil {
		t.Fatal(err)
	}
	newCutoff := oldCutoff + 1000
	if _, err := registry.ApplyRevocation(revokedMember, newCutoff); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	records, err := registry.Records()
	if err != nil || len(records) != 1 || records[0].IssuedAt != newRelease.IssuedAt {
		t.Fatalf("release at old deadline = %+v, %v", records, err)
	}
	var cutoffs []PrivateHomeRevocation
	if err := registry.ForEachRevocationPage(10, func(page []PrivateHomeRevocation) error {
		cutoffs = append(cutoffs, page...)
		return nil
	}); err != nil || len(cutoffs) != 1 || cutoffs[0].BeforeIssuedAt != newCutoff {
		t.Fatalf("cutoff at old deadline = %+v, %v", cutoffs, err)
	}
	now = now.Add(time.Second)
	if records, err = registry.Records(); err != nil || len(records) != 0 {
		t.Fatalf("release at current deadline = %+v, %v", records, err)
	}
	cutoffs = nil
	if err := registry.ForEachRevocationPage(10, func(page []PrivateHomeRevocation) error {
		cutoffs = append(cutoffs, page...)
		return nil
	}); err != nil || len(cutoffs) != 0 {
		t.Fatalf("cutoff at current deadline = %+v, %v", cutoffs, err)
	}
}

func TestTrustedRevocationIsStoredWhenLiveRegistryIsFull(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	home := privateHomeKeyHex(privateHomeKey(t))
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: 1, MaxTTL: 3600, AllowedHomes: []string{home}, Now: func() time.Time { return now },
	})
	occupiedKey, revokedKey := privateHomeKey(t), privateHomeKey(t)
	occupied := signPrivateHome(t, occupiedKey, PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: privateHomeKeyHex(occupiedKey), Homes: []string{home},
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err := registry.Apply(context.Background(), occupied); err != nil {
		t.Fatal(err)
	}
	cutoff := now.UnixMilli()
	if changed, err := registry.ApplyRevocation(privateHomeKeyHex(revokedKey), cutoff); err != nil || !changed {
		t.Fatalf("revocation at full registry = %v, %v", changed, err)
	}
	release := signPrivateHome(t, occupiedKey, PrivateHomeRecord{
		Kind: PrivateHomeRelease, Member: occupied.Member, Homes: []string{}, IssuedAt: occupied.IssuedAt + 1,
	})
	if err := registry.Apply(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	older := signPrivateHome(t, revokedKey, PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: privateHomeKeyHex(revokedKey), Homes: []string{home},
		IssuedAt: cutoff, ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err := registry.Apply(context.Background(), older); !errors.Is(err, ErrPrivateHomeStale) {
		t.Fatalf("covered claim error = %v", err)
	}
	newMember := privateHomeKey(t)
	claim := signPrivateHome(t, newMember, PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: privateHomeKeyHex(newMember), Homes: []string{home},
		IssuedAt: cutoff + 1, ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err := registry.Apply(context.Background(), claim); !errors.Is(err, ErrPrivateHomeLimit) {
		t.Fatalf("claim while cutoff store is full = %v", err)
	}
}

func TestPrivateHomeExpiryWorkIsChunkedAndReadsHideOverdueClaims(t *testing.T) {
	oldChunk := privateHomeExpiryChunk
	privateHomeExpiryChunk = 10
	defer func() { privateHomeExpiryChunk = oldChunk }()
	now := time.Unix(2_000_000_000, 0)
	store, err := NewStore(t.TempDir(), Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{MaxMembers: 1000, MaxTTL: 3600, Now: func() time.Time { return now }})
	batch := new(leveldb.Batch)
	for i := 0; i < 1000; i++ {
		member := fmt.Sprintf("02%064x", i+1)
		record := PrivateHomeRecord{Kind: PrivateHomeClaim, Member: member, IssuedAt: now.Add(-time.Hour).UnixMilli(), ExpiresAt: now.Unix()}
		raw, _ := json.Marshal(record)
		batch.Put(privateHomeRecordKey(member), raw)
	}
	if err := store.db.Write(batch, nil); err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("02%064x", 1000)
	if _, ok, err := registry.Current(target); err != nil || ok {
		t.Fatalf("overdue claim returned: current=%v error=%v", ok, err)
	}
	if rows := countPrivateHomeRows(t, store); rows != 990 {
		t.Fatalf("rows after one expiry invocation = %d, want 990", rows)
	}
	message := &Message{
		MessageID: "between-expiry-chunks", Sender: testIdentity(t), Recipient: testIdentity(t),
		MessageBox: "inbox", Body: "ciphertext", Timestamp: now.Unix(),
	}
	if inserted, err := store.Deliver(message, message.Sender); err != nil || !inserted {
		t.Fatalf("delivery between chunks = %v, %v", inserted, err)
	}
}
