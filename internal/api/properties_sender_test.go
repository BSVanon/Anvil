package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
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

type senderPropertyWatcher struct {
	mu       sync.Mutex
	spent    bool
	checkErr error
	callback func(string, string)
}

func (w *senderPropertyWatcher) Check(context.Context, string) (bool, string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.spent, "", w.checkErr
}

func (*senderPropertyWatcher) Watch(string, string) error                  { return nil }
func (*senderPropertyWatcher) Unwatch(string, string)                      {}
func (w *senderPropertyWatcher) OnSpent(_ string, fn func(string, string)) { w.callback = fn }

type senderPropertyFixture struct {
	subject   *ec.PrivateKey
	certifier *ec.PrivateKey
	typ       string
	outpoint  *transaction.Outpoint
	watcher   *senderPropertyWatcher
	now       time.Time
}

func newSenderPropertyFixture(t *testing.T) *senderPropertyFixture {
	t.Helper()
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	typeBytes := make([]byte, 32)
	for i := range typeBytes {
		typeBytes[i] = 7
	}
	return &senderPropertyFixture{
		subject: subject, certifier: certifier,
		typ:      base64.StdEncoding.EncodeToString(typeBytes),
		outpoint: &transaction.Outpoint{Txid: chainhash.HashH([]byte("sender admission")), Index: 3},
		watcher:  &senderPropertyWatcher{}, now: time.Unix(10_000, 0),
	}
}

func (f *senderPropertyFixture) certificate(t *testing.T, subject *ec.PublicKey, outpoint *transaction.Outpoint) *certificates.VerifiableCertificate {
	t.Helper()
	serial := make([]byte, 32)
	serial[0] = 4
	cert := &certificates.Certificate{
		Type: wallet.StringBase64(f.typ), SerialNumber: wallet.StringBase64(base64.StdEncoding.EncodeToString(serial)),
		Subject: *subject, Certifier: *f.certifier.PubKey(), RevocationOutpoint: outpoint,
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
	}
	signer, err := wallet.NewCompletedProtoWallet(f.certifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(t.Context(), signer); err != nil {
		t.Fatal(err)
	}
	return certificates.NewVerifiableCertificate(cert, nil)
}

func (f *senderPropertyFixture) gate(t *testing.T, alter func(*certgate.Config)) *certgate.Gate {
	t.Helper()
	cfg := certgate.Config{
		Certifiers: []string{hex.EncodeToString(f.certifier.PubKey().Compressed())}, Types: []string{f.typ},
		RevocationCheck: "strict", Recheck: time.Minute, Watcher: f.watcher,
		Now: func() time.Time { return f.now },
	}
	if alter != nil {
		alter(&cfg)
	}
	gate, err := certgate.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func assertSenderPropertyResponse(t *testing.T, subject *ec.PrivateKey, gate *certgate.Gate, want int) {
	t.Helper()
	srv, _ := messageHandlerServer(t, messagingOptionsNone())
	srv.identityPub = hex.EncodeToString(subject.PubKey().Compressed())
	srv.certificateGate = CertificateAdmission{Gate: gate, RequireSender: true}
	_, recipient, _ := newKeyWallet(t)
	response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": recipient, "messageBox": "box", "body": "hello",
	})
	if response.Code != want {
		t.Fatalf("send status = %d, want %d; body %#v", response.Code, want, body)
	}
	if want == http.StatusForbidden && body["code"] != "ERR_SENDER_CERTIFICATE_REQUIRED" {
		t.Fatalf("refusal body = %#v", body)
	}
}

func TestSenderGateRequiresCurrentAdmission(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		f := newSenderPropertyFixture(t)
		gate := f.gate(t, nil)
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), f.outpoint)); err != nil {
			t.Fatal(err)
		}
		gate.SetSpendVerifier(func(context.Context, string, string) error { return nil })
		f.watcher.callback(f.outpoint.String(), hex.EncodeToString(make([]byte, 32)))
		identity := hex.EncodeToString(f.subject.PubKey().Compressed())
		deadline := time.Now().Add(time.Second)
		for gate.Admitted(t.Context(), identity) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		assertSenderPropertyResponse(t, f.subject, gate, http.StatusForbidden)
	})

	t.Run("unrevocable without policy", func(t *testing.T) {
		f := newSenderPropertyFixture(t)
		gate := f.gate(t, nil)
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), &transaction.Outpoint{})); err == nil {
			t.Fatal("unrevocable certificate was admitted")
		}
		assertSenderPropertyResponse(t, f.subject, gate, http.StatusForbidden)
	})

	t.Run("required field absent", func(t *testing.T) {
		f := newSenderPropertyFixture(t)
		gate := f.gate(t, func(c *certgate.Config) { c.RevealFields = map[string][]string{f.typ: {"role"}} })
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), f.outpoint)); err == nil {
			t.Fatal("certificate without required field was admitted")
		}
		assertSenderPropertyResponse(t, f.subject, gate, http.StatusForbidden)
	})

	t.Run("another subject replayed", func(t *testing.T) {
		f := newSenderPropertyFixture(t)
		gate := f.gate(t, nil)
		other, _ := ec.NewPrivateKey()
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, other.PubKey(), f.outpoint)); err == nil {
			t.Fatal("certificate for another subject was admitted")
		}
		assertSenderPropertyResponse(t, f.subject, gate, http.StatusForbidden)
	})

	t.Run("expired with strict lookup error", func(t *testing.T) {
		f := newSenderPropertyFixture(t)
		gate := f.gate(t, nil)
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), f.outpoint)); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(2 * time.Minute)
		f.watcher.mu.Lock()
		f.watcher.checkErr = errors.New("lookup failed")
		f.watcher.mu.Unlock()
		assertSenderPropertyResponse(t, f.subject, gate, http.StatusForbidden)
	})

	t.Run("valid admission", func(t *testing.T) {
		f := newSenderPropertyFixture(t)
		gate := f.gate(t, nil)
		if err := gate.Verify(t.Context(), f.subject.PubKey(), f.certificate(t, f.subject.PubKey(), f.outpoint)); err != nil {
			t.Fatal(err)
		}
		assertSenderPropertyResponse(t, f.subject, gate, http.StatusOK)
	})
}
