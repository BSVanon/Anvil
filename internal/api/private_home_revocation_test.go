package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type privateHomeSpendWatcher struct {
	mu       sync.Mutex
	callback func(string, string)
	outpoint string
	spent    bool
}

func (w *privateHomeSpendWatcher) Check(context.Context, string) (bool, string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.spent, "", nil
}

func TestPersistedPrivateHomeAdmissionIsRevokedAfterRestart(t *testing.T) {
	member, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	home, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	homeHex := hex.EncodeToString(home.PubKey().Compressed())
	path := t.TempDir()
	store, err := messaging.NewStore(path, messaging.Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	registry := messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
		MaxMembers: 10, MaxTTL: 3600, AllowedHomes: []string{homeHex},
	})
	claim := signedHTTPPrivateHome(t, member, []string{homeHex}, time.Now().UnixMilli())
	outpoint := (&transaction.Outpoint{Txid: chainhash.HashH([]byte("persisted private home admission")), Index: 2}).String()
	if err := registry.ApplyAdmitted(t.Context(), claim, outpoint); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = messaging.NewStore(path, messaging.Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry = messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
		MaxMembers: 10, MaxTTL: 3600, AllowedHomes: []string{homeHex},
	})

	certifier, _ := ec.NewPrivateKey()
	typeBytes := make([]byte, 32)
	typeBytes[0] = 1
	watcher := &privateHomeSpendWatcher{spent: true}
	gate, err := certgate.New(certgate.Config{
		Certifiers: []string{hex.EncodeToString(certifier.PubKey().Compressed())},
		Types:      []string{base64.StdEncoding.EncodeToString(typeBytes)}, RevocationCheck: "strict",
		Recheck: time.Hour, Watcher: watcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := ReconcilePrivateHomeAdmissions(t.Context(), registry, gate)
	if err != nil {
		t.Fatal(err)
	}
	if len(reconciled) != 1 || reconciled[0].Member != claim.Member || reconciled[0].BeforeIssuedAt != claim.IssuedAt {
		t.Fatalf("emitted startup revocations = %+v", reconciled)
	}
	if _, current, err := registry.Current(claim.Member); err != nil || current {
		t.Fatalf("persisted claim current=%v, error=%v", current, err)
	}
	var cutoffs []messaging.PrivateHomeRevocation
	if err := registry.ForEachRevocationPage(10, func(page []messaging.PrivateHomeRevocation) error {
		cutoffs = append(cutoffs, page...)
		return nil
	}); err != nil || len(cutoffs) != 1 || cutoffs[0].BeforeIssuedAt != claim.IssuedAt {
		t.Fatalf("startup revocation cutoffs = %+v, %v", cutoffs, err)
	}
}
func (w *privateHomeSpendWatcher) Watch(outpoint, _ string) error {
	w.mu.Lock()
	w.outpoint = outpoint
	w.mu.Unlock()
	return nil
}
func (*privateHomeSpendWatcher) Unwatch(string, string) {}
func (w *privateHomeSpendWatcher) OnSpent(_ string, callback func(string, string)) {
	w.mu.Lock()
	w.callback = callback
	w.mu.Unlock()
}
func (w *privateHomeSpendWatcher) trigger() {
	w.mu.Lock()
	callback, outpoint := w.callback, w.outpoint
	w.mu.Unlock()
	callback(outpoint, "revocation-spend")
}

func TestCertificateRevocationRemovesPrivateHomeClaim(t *testing.T) {
	member, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	home, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	homeHex := hex.EncodeToString(home.PubKey().Compressed())
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
		MaxMembers: 10, MaxTTL: 3600, AllowedHomes: []string{homeHex},
	})
	claim := signedHTTPPrivateHome(t, member, []string{homeHex}, time.Now().UnixMilli())
	revocationOutpoint := &transaction.Outpoint{Txid: chainhash.HashH([]byte("private home revocation")), Index: 1}
	if err := registry.ApplyAdmitted(t.Context(), claim, revocationOutpoint.String()); err != nil {
		t.Fatal(err)
	}

	certifier, _ := ec.NewPrivateKey()
	typeBytes := make([]byte, 32)
	for i := range typeBytes {
		typeBytes[i] = 1
	}
	typeBase64 := base64.StdEncoding.EncodeToString(typeBytes)
	watcher := &privateHomeSpendWatcher{}
	gate, err := certgate.New(certgate.Config{
		Certifiers: []string{hex.EncodeToString(certifier.PubKey().Compressed())}, Types: []string{typeBase64},
		RevocationCheck: "strict", Recheck: time.Hour, Watcher: watcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	gate.SetSpendVerifier(func(context.Context, string, string) error { return nil })
	serial := base64.StdEncoding.EncodeToString(make([]byte, 32))
	certificate := &certificates.Certificate{
		Type: wallet.StringBase64(typeBase64), SerialNumber: wallet.StringBase64(serial), Subject: *member.PubKey(),
		Certifier: *certifier.PubKey(), RevocationOutpoint: revocationOutpoint,
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
	}
	signer, _ := wallet.NewCompletedProtoWallet(certifier)
	if err := certificate.Sign(t.Context(), signer); err != nil {
		t.Fatal(err)
	}
	if err := gate.Verify(t.Context(), member.PubKey(), certificates.NewVerifiableCertificate(certificate, nil)); err != nil {
		t.Fatal(err)
	}
	_ = NewServer(ServerConfig{
		MsgStore: store, MessagingPolicy: MessagingPolicy{PrivateHomes: registry}, CertificateGate: CertificateAdmission{Gate: gate},
	})
	watcher.trigger()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, ok, _ := registry.Current(claim.Member); !ok {
			if gate.AdmissionMatches(claim.Member, revocationOutpoint.String()) {
				t.Fatal("revoked claim left its admission pinned")
			}
			records, err := registry.Records()
			if err != nil || len(records) != 1 || records[0].Kind != messaging.PrivateHomeRelease {
				t.Fatalf("revocation tombstone = %+v, %v", records, err)
			}
			var cutoffs []messaging.PrivateHomeRevocation
			if err := registry.ForEachRevocationPage(10, func(page []messaging.PrivateHomeRevocation) error {
				cutoffs = append(cutoffs, page...)
				return nil
			}); err != nil || len(cutoffs) != 1 || cutoffs[0].Member != claim.Member {
				t.Fatalf("revocation cutoffs = %+v, %v", cutoffs, err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("certificate revocation did not remove private home claim")
}
