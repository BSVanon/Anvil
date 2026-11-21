package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type apiCertWatcher struct{}

func (apiCertWatcher) Check(context.Context, string) (bool, string, error) { return false, "", nil }
func (apiCertWatcher) Watch(string, string) error                          { return nil }
func (apiCertWatcher) Unwatch(string, string)                              {}
func (apiCertWatcher) OnSpent(string, func(string, string))                {}

func apiCertificateGate(t *testing.T, subject *ec.PrivateKey) *certgate.Gate {
	t.Helper()
	certifier, _ := ec.NewPrivateKey()
	typBytes := make([]byte, 32)
	for i := range typBytes {
		typBytes[i] = 1
	}
	typ := base64.StdEncoding.EncodeToString(typBytes)
	gate, err := certgate.New(certgate.Config{
		Certifiers: []string{hex.EncodeToString(certifier.PubKey().Compressed())}, Types: []string{typ},
		RevocationCheck: "strict", Recheck: time.Hour, Watcher: apiCertWatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	serial := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cert := &certificates.Certificate{
		Type: wallet.StringBase64(typ), SerialNumber: wallet.StringBase64(serial), Subject: *subject.PubKey(),
		Certifier: *certifier.PubKey(), RevocationOutpoint: &transaction.Outpoint{Txid: chainhash.HashH([]byte("api certificate")), Index: 1},
		Fields: map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
	}
	signer, _ := wallet.NewCompletedProtoWallet(certifier)
	if err := cert.Sign(t.Context(), signer); err != nil {
		t.Fatal(err)
	}
	if err := gate.Verify(t.Context(), subject.PubKey(), certificates.NewVerifiableCertificate(cert, nil)); err != nil {
		t.Fatal(err)
	}
	return gate
}

func TestSenderCertificateGate(t *testing.T) {
	t.Run("missing certificate", func(t *testing.T) {
		srv, _ := messageHandlerServer(t, messagingOptionsNone())
		srv.certificateGate.RequireSender = true
		_, recipient, _ := newKeyWallet(t)
		response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{"recipient": recipient, "messageBox": "box", "body": "hello"})
		if response.Code != 403 || body["code"] != "ERR_SENDER_CERTIFICATE_REQUIRED" {
			t.Fatalf("response = %d, %#v", response.Code, body)
		}
	})
	t.Run("verified certificate", func(t *testing.T) {
		srv, _ := messageHandlerServer(t, messagingOptionsNone())
		subject, _ := ec.NewPrivateKey()
		srv.identityPub = hex.EncodeToString(subject.PubKey().Compressed())
		srv.certificateGate = CertificateAdmission{Gate: apiCertificateGate(t, subject), RequireSender: true}
		_, recipient, _ := newKeyWallet(t)
		response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{"recipient": recipient, "messageBox": "box", "body": "hello"})
		if response.Code != 200 || body["status"] != "success" {
			t.Fatalf("response = %d, %#v", response.Code, body)
		}
	})
}

func TestCertificateGateOffDoesNotRequestCertificates(t *testing.T) {
	for name, admission := range map[string]CertificateAdmission{
		"policy absent":                {},
		"policy configured but unused": {Gate: apiCertificateGate(t, mustPrivateKey(t))},
	} {
		t.Run(name, func(t *testing.T) {
			srv := &Server{certificateGate: admission}
			var cfg middleware.AuthMiddlewareConfig
			for _, option := range srv.certificateAuthOptions() {
				option(&cfg)
			}
			if !cfg.AllowUnauthenticated || cfg.CertificatesToRequest != nil || cfg.OnCertificatesReceived != nil {
				t.Fatalf("gate-off auth options changed the BRC-31 handshake: %+v", cfg)
			}
		})
	}
}

func TestEitherHTTPGateRequestsCertificates(t *testing.T) {
	gate := apiCertificateGate(t, mustPrivateKey(t))
	for name, admission := range map[string]CertificateAdmission{
		"sender":       {Gate: gate, RequireSender: true},
		"registration": {Gate: gate, Registration: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})},
	} {
		t.Run(name, func(t *testing.T) {
			var cfg middleware.AuthMiddlewareConfig
			for _, option := range (&Server{certificateGate: admission}).certificateAuthOptions() {
				option(&cfg)
			}
			if cfg.CertificatesToRequest == nil || len(cfg.CertificatesToRequest.CertificateTypes) == 0 || cfg.OnCertificatesReceived == nil {
				t.Fatalf("certificate request options missing: %+v", cfg)
			}
		})
	}
}

func mustPrivateKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func messagingOptionsNone() messaging.Options { return messaging.Options{} }
