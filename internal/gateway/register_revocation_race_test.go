package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type revokingRegistrationBody struct {
	reader  *bytes.Reader
	onFirst func() error
	once    sync.Once
	err     error
}

func (b *revokingRegistrationBody) Read(p []byte) (int, error) {
	b.once.Do(func() { b.err = b.onFirst() })
	if b.err != nil {
		return 0, b.err
	}
	return b.reader.Read(p)
}

func (b *revokingRegistrationBody) Close() error { return nil }

func TestRegistrationRefusesRevocationDuringBodyRead(t *testing.T) {
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	typeBytes := make([]byte, 32)
	for i := range typeBytes {
		typeBytes[i] = 7
	}
	typ := base64.StdEncoding.EncodeToString(typeBytes)
	outpoint := &transaction.Outpoint{Txid: chainhash.HashH([]byte("registration body revocation")), Index: 1}
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
	r := NewRegistrar(filepath.Join(dir, "operator.conf"), filepath.Join(dir, "registrations.conf"), "", gate, nil)
	other := registrationIdentity('2')
	if _, _, err := r.register(other, "existing.example"); err != nil {
		t.Fatal(err)
	}
	identity := hex.EncodeToString(subject.PubKey().Compressed())
	revoked := make(chan struct{})
	gate.OnRevoke("test", func(string) { close(revoked) })
	gate.SetSpendVerifier(func(context.Context, string, string) error { return nil })
	body := &revokingRegistrationBody{
		reader: bytes.NewReader([]byte(`{"domain":"racing.example"}`)),
		onFirst: func() error {
			watcher.callback(outpoint.String(), strings.Repeat("e", 64))
			select {
			case <-revoked:
				if !gate.Admitted(t.Context(), identity) {
					return nil
				}
				return errors.New("confirmed spend left the identity admitted")
			case <-time.After(time.Second):
				return errors.New("confirmed spend did not revoke the identity")
			}
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/gateway/sites", body)
	response := httptest.NewRecorder()
	r.add(response, req, identity)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "ERR_CERTIFICATE_REQUIRED") {
		t.Fatalf("response = %d, %s", response.Code, response.Body.String())
	}
	contents, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "racing.example") {
		t.Fatal("revoked identity retained its registration")
	}
	if !strings.Contains(string(contents), "existing.example") {
		t.Fatal("revocation removed another identity's registration")
	}
}
