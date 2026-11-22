package messaging

import (
	"context"
	"errors"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestTrustedRevocationSurvivesSignedReleasePressure(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	home := privateHomeKeyHex(privateHomeKey(t))
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: 3, MaxTTL: 3600, AllowedHomes: []string{home}, Now: func() time.Time { return now },
	})
	revokedMember := privateHomeKey(t)
	claim := signPrivateHome(t, revokedMember, PrivateHomeRecord{
		Kind: PrivateHomeClaim, Member: privateHomeKeyHex(revokedMember), Homes: []string{home},
		IssuedAt: now.Add(-2 * time.Second).UnixMilli(), ExpiresAt: now.Add(30 * time.Minute).Unix(),
	})
	if err := registry.Apply(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	if changed, err := registry.ApplyRevocation(claim.Member, claim.IssuedAt); err != nil || !changed {
		t.Fatalf("revocation = %v, %v", changed, err)
	}

	for i := 0; i < 3; i++ {
		member := privateHomeKey(t)
		release := signPrivateHome(t, member, PrivateHomeRecord{
			Kind: PrivateHomeRelease, Member: privateHomeKeyHex(member), Homes: []string{},
			IssuedAt: now.Add(time.Duration(i-1) * time.Millisecond).UnixMilli(),
		})
		if err := registry.Apply(context.Background(), release); err != nil {
			t.Fatal(err)
		}
	}
	if err := registry.Apply(context.Background(), claim); !errors.Is(err, ErrPrivateHomeStale) {
		t.Fatalf("replayed revoked claim error = %v", err)
	}
	var cutoffs []PrivateHomeRevocation
	if err := registry.ForEachRevocationPage(10, func(page []PrivateHomeRevocation) error {
		cutoffs = append(cutoffs, page...)
		return nil
	}); err != nil || len(cutoffs) != 1 || cutoffs[0].Member != claim.Member {
		t.Fatalf("trusted cutoffs = %+v, %v", cutoffs, err)
	}
}

func TestPrivateHomeBatchDoesNotRescanPopulatedRegistry(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	store, err := NewStore(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	home := privateHomeKeyHex(privateHomeKey(t))
	registry := NewPrivateHomeStore(store, PrivateHomeOptions{
		MaxMembers: 250, MaxTTL: 7200, AllowedHomes: []string{home}, Now: func() time.Time { return now },
	})
	members := make([]*ec.PrivateKey, 200)
	for i := range members {
		members[i] = privateHomeKey(t)
		record := signPrivateHome(t, members[i], PrivateHomeRecord{
			Kind: PrivateHomeClaim, Member: privateHomeKeyHex(members[i]), Homes: []string{home},
			IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Hour).Unix(),
		})
		if err := registry.Apply(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	fullScans := 0
	registry.onFullScan = func() { fullScans++ }
	renewals := make([]PrivateHomeRecord, len(members))
	for i, member := range members {
		renewals[i] = signPrivateHome(t, member, PrivateHomeRecord{
			Kind: PrivateHomeClaim, Member: privateHomeKeyHex(member), Homes: []string{home},
			IssuedAt: now.Add(time.Second).UnixMilli(), ExpiresAt: now.Add(2 * time.Hour).Unix(),
		})
	}
	results := registry.ApplyBatch(context.Background(), renewals)
	for i, result := range results {
		if result != nil {
			t.Fatalf("renewal %d: %v", i, result)
		}
	}
	if fullScans != 0 {
		t.Fatalf("batch performed %d full registry scans", fullScans)
	}
}
