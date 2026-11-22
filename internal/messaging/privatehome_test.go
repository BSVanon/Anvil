package messaging

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func privateHomeKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func privateHomeKeyHex(key *ec.PrivateKey) string {
	return hex.EncodeToString(key.PubKey().Compressed())
}

func signPrivateHome(t *testing.T, key *ec.PrivateKey, record PrivateHomeRecord) PrivateHomeRecord {
	t.Helper()
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: privateHomeProtocol, KeyID: privateHomeKeyID,
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		},
		Data: PrivateHomeCanonicalBytes(record),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	record.Signature = hex.EncodeToString(result.Signature.Serialize())
	return record
}

func TestPrivateHomeProtoWalletSignatureAndTampering(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	member := privateHomeKey(t)
	home := privateHomeKeyHex(privateHomeKey(t))
	record := signPrivateHome(t, member, PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: privateHomeKeyHex(member), Homes: []string{home},
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	verifier := newPrivateHomeVerifier(24*60*60, []string{home}, func() time.Time { return now })
	if err := verifier.Validate(context.Background(), record); err != nil {
		t.Fatalf("ProtoWallet signature did not verify: %v", err)
	}

	tests := map[string]func(*PrivateHomeRecord){
		"kind":      func(r *PrivateHomeRecord) { r.Kind = PrivateHomeRelease },
		"member":    func(r *PrivateHomeRecord) { r.Member = home },
		"homes":     func(r *PrivateHomeRecord) { r.Homes = []string{} },
		"issuedAt":  func(r *PrivateHomeRecord) { r.IssuedAt-- },
		"expiresAt": func(r *PrivateHomeRecord) { r.ExpiresAt-- },
		"signature": func(r *PrivateHomeRecord) { r.Signature = r.Signature[:len(r.Signature)-2] + "00" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := record
			changed.Homes = append([]string(nil), record.Homes...)
			mutate(&changed)
			if err := verifier.Validate(context.Background(), changed); err == nil {
				t.Fatal("tampered record verified")
			}
		})
	}
}

func TestPrivateHomeRecordShapeAndTimeBounds(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	member := privateHomeKey(t)
	homes := []string{
		privateHomeKeyHex(privateHomeKey(t)), privateHomeKeyHex(privateHomeKey(t)),
		privateHomeKeyHex(privateHomeKey(t)), privateHomeKeyHex(privateHomeKey(t)),
	}
	sort.Strings(homes)
	verifier := newPrivateHomeVerifier(3600, homes[:3], func() time.Time { return now })
	base := PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: privateHomeKeyHex(member), Homes: homes[:1],
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	}
	tests := map[string]func(*PrivateHomeRecord){
		"unsorted":              func(r *PrivateHomeRecord) { r.Homes = []string{homes[1], homes[0]} },
		"duplicate":             func(r *PrivateHomeRecord) { r.Homes = []string{homes[0], homes[0]} },
		"zero homes":            func(r *PrivateHomeRecord) { r.Homes = nil },
		"four homes":            func(r *PrivateHomeRecord) { r.Homes = homes },
		"outside allowed peers": func(r *PrivateHomeRecord) { r.Homes = homes[3:] },
		"expired":               func(r *PrivateHomeRecord) { r.ExpiresAt = now.Unix() },
		"expiry past maximum":   func(r *PrivateHomeRecord) { r.ExpiresAt = now.Add(3601 * time.Second).Unix() },
		"future issuedAt":       func(r *PrivateHomeRecord) { r.IssuedAt = now.Add(10*time.Minute + time.Millisecond).UnixMilli() },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := base
			record.Homes = append([]string(nil), base.Homes...)
			mutate(&record)
			record = signPrivateHome(t, member, record)
			if err := verifier.Validate(context.Background(), record); err == nil {
				t.Fatal("invalid record verified")
			}
		})
	}
	missingReleaseHomes := signPrivateHome(t, member, PrivateHomeRecord{
		Kind: PrivateHomeRelease, Member: privateHomeKeyHex(member), IssuedAt: now.UnixMilli(),
	})
	if err := verifier.Validate(context.Background(), missingReleaseHomes); err == nil {
		t.Fatal("release without homes array verified")
	}
}

func TestPrivateHomeNewestWinsPersistsAndBoundsMembers(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	path := t.TempDir()
	messages, err := NewStore(path, Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	memberA, memberB, home := privateHomeKey(t), privateHomeKey(t), privateHomeKeyHex(privateHomeKey(t))
	newRegistry := func(store *Store) *PrivateHomeStore {
		return NewPrivateHomeStore(store, PrivateHomeOptions{
			MaxMembers: 1, MaxTTL: 3600, AllowedHomes: []string{home}, Now: func() time.Time { return now },
		})
	}
	registry := newRegistry(messages)
	claim := func(key *ec.PrivateKey, issued int64) PrivateHomeRecord {
		return signPrivateHome(t, key, PrivateHomeRecord{
			Kind: PrivateHomeClaim, Member: privateHomeKeyHex(key), Homes: []string{home},
			IssuedAt: issued, ExpiresAt: issued/1000 + 3600,
		})
	}
	first := claim(memberA, now.UnixMilli())
	if err := registry.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := registry.Apply(context.Background(), claim(memberA, first.IssuedAt-1)); !errors.Is(err, ErrPrivateHomeStale) {
		t.Fatalf("older claim error = %v", err)
	}
	olderRelease := signPrivateHome(t, memberA, PrivateHomeRecord{
		Kind: PrivateHomeRelease, Member: privateHomeKeyHex(memberA), Homes: []string{}, IssuedAt: first.IssuedAt - 1,
	})
	if err := registry.Apply(context.Background(), olderRelease); !errors.Is(err, ErrPrivateHomeStale) {
		t.Fatalf("older release error = %v", err)
	}
	if err := registry.Apply(context.Background(), claim(memberA, first.IssuedAt+1)); err != nil {
		t.Fatalf("renewal refused: %v", err)
	}
	if err := registry.Apply(context.Background(), claim(memberB, first.IssuedAt+2)); !errors.Is(err, ErrPrivateHomeLimit) {
		t.Fatalf("new member over cap error = %v", err)
	}
	release := signPrivateHome(t, memberA, PrivateHomeRecord{
		Kind: PrivateHomeRelease, Member: privateHomeKeyHex(memberA), Homes: []string{}, IssuedAt: first.IssuedAt + 3,
	})
	if err := registry.Apply(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	if err := registry.Apply(context.Background(), claim(memberA, first.IssuedAt+2)); !errors.Is(err, ErrPrivateHomeStale) {
		t.Fatalf("release did not block replay: %v", err)
	}
	if err := messages.Close(); err != nil {
		t.Fatal(err)
	}
	messages, err = NewStore(path, Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	defer messages.Close()
	registry = newRegistry(messages)
	records, err := registry.Records()
	if err != nil || len(records) != 1 || records[0].Kind != PrivateHomeRelease {
		t.Fatalf("persisted tombstone = %+v, %v", records, err)
	}
	now = now.Add(3601 * time.Second)
	records, err = registry.Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("expired tombstone = %+v, %v", records, err)
	}
}

func TestPrivateHomeResolverPrecedesAndExpiresToAdvert(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	messages, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer messages.Close()
	member, g1, g2, g3 := privateHomeKey(t), privateHomeKeyHex(privateHomeKey(t)), privateHomeKeyHex(privateHomeKey(t)), privateHomeKeyHex(privateHomeKey(t))
	homes := []string{g1, g2}
	sort.Strings(homes)
	registry := NewPrivateHomeStore(messages, PrivateHomeOptions{MaxMembers: 10, MaxTTL: 3600, AllowedHomes: append(homes, g3), Now: func() time.Time { return now }})
	record := signPrivateHome(t, member, PrivateHomeRecord{Kind: PrivateHomeClaim, Member: privateHomeKeyHex(member), Homes: homes, IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Hour).Unix()})
	if err := registry.Apply(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	fallback := HomeResolverFunc(func(string) (Resolution, error) { return Resolution{State: Home}, nil })
	res, err := NewPrivateHomeResolver(registry, homes[0], fallback).Resolve(record.Member)
	if err != nil || res.State != Home || !res.HasOtherHost {
		t.Fatalf("home resolution = %+v, %v", res, err)
	}
	res, err = NewPrivateHomeResolver(registry, g3, fallback).Resolve(record.Member)
	if err != nil || res.State != Elsewhere {
		t.Fatalf("elsewhere resolution = %+v, %v", res, err)
	}
	now = now.Add(time.Hour)
	res, err = NewPrivateHomeResolver(registry, g3, fallback).Resolve(record.Member)
	if err != nil || res.State != Home {
		t.Fatalf("expired fallback = %+v, %v", res, err)
	}
}

func TestPrivateHomeTombstonesEvictOldestAtCap(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	messages, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer messages.Close()
	registry := NewPrivateHomeStore(messages, PrivateHomeOptions{
		MaxMembers: 1, MaxTTL: 3600, Now: func() time.Time { return now },
	})
	first, second := privateHomeKey(t), privateHomeKey(t)
	for i, member := range []*ec.PrivateKey{first, second} {
		release := signPrivateHome(t, member, PrivateHomeRecord{
			Kind: PrivateHomeRelease, Member: privateHomeKeyHex(member), Homes: []string{},
			IssuedAt: now.Add(time.Duration(i-2) * time.Millisecond).UnixMilli(),
		})
		if err := registry.Apply(context.Background(), release); err != nil {
			t.Fatal(err)
		}
	}
	records, err := registry.Records()
	if err != nil || len(records) != 1 || records[0].Member != privateHomeKeyHex(second) {
		t.Fatalf("bounded tombstones = %+v, %v", records, err)
	}
}

type HomeResolverFunc func(string) (Resolution, error)

func (f HomeResolverFunc) Resolve(member string) (Resolution, error) { return f(member) }
