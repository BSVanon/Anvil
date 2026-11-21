package gateway

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type registrationRevocationWatcher struct{ callback func(string, string) }

func (registrationRevocationWatcher) Check(context.Context, string) (bool, string, error) {
	return false, "", nil
}
func (registrationRevocationWatcher) Watch(string, string) error                   { return nil }
func (registrationRevocationWatcher) Unwatch(string, string)                       {}
func (w *registrationRevocationWatcher) OnSpent(_ string, fn func(string, string)) { w.callback = fn }

func TestVerifiedRevocationRemovesRegistrations(t *testing.T) {
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	typeBytes := make([]byte, 32)
	for i := range typeBytes {
		typeBytes[i] = 6
	}
	typ := base64.StdEncoding.EncodeToString(typeBytes)
	outpoint := &transaction.Outpoint{Txid: chainhash.HashH([]byte("registration revocation")), Index: 1}
	watcher := &registrationRevocationWatcher{}
	gate, err := certgate.New(certgate.Config{
		Certifiers: []string{hex.EncodeToString(certifier.PubKey().Compressed())}, Types: []string{typ},
		RevocationCheck: "strict", Recheck: time.Hour, Watcher: watcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := &certificates.Certificate{
		Type: wallet.StringBase64(typ), SerialNumber: wallet.StringBase64(base64.StdEncoding.EncodeToString(make([]byte, 32))),
		Subject: *subject.PubKey(), Certifier: *certifier.PubKey(), RevocationOutpoint: outpoint,
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
	}
	signer, _ := wallet.NewCompletedProtoWallet(certifier)
	if err := cert.Sign(t.Context(), signer); err != nil {
		t.Fatal(err)
	}
	if err := gate.Verify(t.Context(), subject.PubKey(), certificates.NewVerifiableCertificate(cert, nil)); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	registrationPath := filepath.Join(dir, "registrations.conf")
	r := NewRegistrar(filepath.Join(dir, "operator.conf"), registrationPath, "", gate, nil)
	identity := hex.EncodeToString(subject.PubKey().Compressed())
	if _, _, err := r.register(identity, "revoked.example"); err != nil {
		t.Fatal(err)
	}
	gate.SetSpendVerifier(func(context.Context, string, string) error { return nil })
	watcher.callback(outpoint.String(), strings.Repeat("a", 64))

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		raw, readErr := os.ReadFile(registrationPath)
		if readErr == nil && !strings.Contains(string(raw), "revoked.example") {
			break
		}
		time.Sleep(time.Millisecond)
	}
	raw, err := os.ReadFile(registrationPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "revoked.example") {
		t.Fatal("verified revocation left the identity's registration")
	}
	if gate.Admitted(t.Context(), identity) {
		t.Fatal("verified revocation left the identity admitted")
	}
}
