package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/gateway"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/authpayload"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
)

type pipeListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddress("in-process") }

type pipeAddress string

func (a pipeAddress) Network() string { return string(a) }
func (a pipeAddress) String() string  { return string(a) }

func newPipeHTTPClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	listener := newPipeListener()
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		select {
		case listener.connections <- server:
			return client, nil
		case <-ctx.Done():
			_ = client.Close()
			_ = server.Close()
			return nil, ctx.Err()
		case <-listener.closed:
			_ = client.Close()
			_ = server.Close()
			return nil, net.ErrClosed
		}
	}}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = server.Close()
		_ = listener.Close()
	})
	return &http.Client{Transport: transport}
}

type certificateClientWallet struct {
	wallet.Interface
	certificates wallet.Interface
}

func (w certificateClientWallet) ListCertificates(ctx context.Context, args wallet.ListCertificatesArgs, originator string) (*wallet.ListCertificatesResult, error) {
	return w.certificates.ListCertificates(ctx, args, originator)
}

func (w certificateClientWallet) ProveCertificate(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
	return w.certificates.ProveCertificate(ctx, args, originator)
}

func certificateTestServer(t *testing.T) (*Server, wallet.Interface, string) {
	t.Helper()
	certifier, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	typeID, err := wallet.CertificateTypeFromString("anvil membership")
	if err != nil {
		t.Fatal(err)
	}
	typeBase64 := base64.StdEncoding.EncodeToString(typeID.Bytes())
	clientKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	baseWallet, err := wallet.NewCompletedProtoWallet(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateWallet := wallet.NewTestWallet(t, clientKey)
	manager := testcertificates.NewManager(t, certificateWallet)
	manager.CertificateForTest().WithType("anvil membership").WithFieldValue("role", "member").IssueWithCertifier(certifier)
	clientWallet := certificateClientWallet{Interface: baseWallet, certificates: certificateWallet}
	registrationPath := filepath.Join(t.TempDir(), "gateway-registrations.conf")
	srv, _ := buildTestServerBRC31(t, func(nodeWallet wallet.Interface) CertificateAdmission {
		gate, err := certgate.New(certgate.Config{
			Certifiers:       []string{hex.EncodeToString(certifier.PubKey().Compressed())},
			Types:            []string{typeBase64},
			RevealFields:     map[string][]string{typeBase64: {"role"}},
			AllowUnrevocable: map[string]bool{typeBase64: true},
			RevocationCheck:  "strict",
			Recheck:          time.Hour,
			Wallet:           nodeWallet,
			Watcher:          apiCertWatcher{},
		})
		if err != nil {
			t.Fatal(err)
		}
		registrar := gateway.NewRegistrar(filepath.Join(t.TempDir(), "operator.conf"), registrationPath, "gateway.example", gate, slog.Default())
		return CertificateAdmission{Gate: gate, Registration: registrar}
	})
	return srv, clientWallet, registrationPath
}

// certificateHTTPTransport treats a successful certificate-response POST as
// complete. This keeps the test focused on server behavior despite go-sdk
// v1.7.7 rejecting the empty success body in
// auth/transports/simplified_http_transport.go:143-148.
type certificateHTTPTransport struct {
	baseURL string
	client  *http.Client
	inner   *transports.SimplifiedHTTPTransport
}

func newCertificateHTTPTransport(t *testing.T, client *http.Client) *certificateHTTPTransport {
	t.Helper()
	const baseURL = "http://anvil.test"
	inner, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{BaseURL: baseURL, Client: client})
	if err != nil {
		t.Fatal(err)
	}
	return &certificateHTTPTransport{baseURL: baseURL, client: client, inner: inner}
}

func (t *certificateHTTPTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	return t.inner.OnData(callback)
}

func (t *certificateHTTPTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	return t.inner.GetRegisteredOnData()
}

func (t *certificateHTTPTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	if message.MessageType != auth.MessageTypeCertificateResponse {
		return t.inner.Send(ctx, message)
	}
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+"/.well-known/auth", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := io.ReadAll(response.Body)
		return fmt.Errorf("certificate response status %d: %s", response.StatusCode, raw)
	}
	return nil
}

func requestWithCertificatePeer(ctx context.Context, peer *auth.Peer, path, body string) (*http.Response, error) {
	requestID := bytes.Repeat([]byte{byte(len(path))}, 32)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://anvil.test"+path, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	payload, err := authpayload.FromHTTPRequest(requestID, req)
	if err != nil {
		return nil, err
	}
	responses := make(chan *http.Response, 1)
	listener := peer.ListenForGeneralMessages(func(_ context.Context, sender *ec.PublicKey, responsePayload []byte) error {
		gotID, response, parseErr := authpayload.ToHTTPResponse(responsePayload, authpayload.WithSenderPublicKey(sender))
		if parseErr != nil {
			return parseErr
		}
		if bytes.Equal(gotID, requestID) {
			responses <- response
		}
		return nil
	})
	defer peer.StopListeningForGeneralMessages(listener)
	if err := peer.ToPeer(ctx, payload, nil, 5000); err != nil {
		return nil, err
	}
	select {
	case response := <-responses:
		return response, nil
	case <-time.After(time.Second):
		return nil, fmt.Errorf("authenticated response was not delivered")
	}
}

func fetchWithCertificatePeer(t *testing.T, peer *auth.Peer, path, body string) *http.Response {
	t.Helper()
	response, err := requestWithCertificatePeer(t.Context(), peer, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestRegistrationCertificateRequestRejectsClientWithoutCertificate(t *testing.T) {
	srv, _, _ := certificateTestServer(t)
	_, _, walletWithoutCertificate := newKeyWallet(t)
	transport := newCertificateHTTPTransport(t, newPipeHTTPClient(t, srv.Handler()))
	peer := auth.NewPeer(&auth.PeerOptions{Wallet: walletWithoutCertificate, Transport: transport})
	response, err := requestWithCertificatePeer(t.Context(), peer, "/listMessages", `{"messageBox":"inbox"}`)
	if response != nil {
		defer response.Body.Close()
	}
	if err == nil && response.StatusCode < http.StatusBadRequest {
		t.Fatalf("client without a certificate authenticated: status %d", response.StatusCode)
	}
}

func TestAdmittedCertificateClientCanListMessagesAndRegister(t *testing.T) {
	srv, clientWallet, registrationPath := certificateTestServer(t)
	identityResult, err := clientWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	identity := hex.EncodeToString(identityResult.PublicKey.Compressed())
	transport := newCertificateHTTPTransport(t, newPipeHTTPClient(t, srv.Handler()))
	peer := auth.NewPeer(&auth.PeerOptions{Wallet: clientWallet, Transport: transport})
	list := fetchWithCertificatePeer(t, peer, "/listMessages", `{"recipient":"`+identity+`","messageBox":"inbox"}`)
	defer list.Body.Close()
	if list.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(list.Body)
		t.Fatalf("list status = %d, body %s", list.StatusCode, body)
	}
	register := fetchWithCertificatePeer(t, peer, "/gateway/sites", `{"domain":"registered.example"}`)
	defer register.Body.Close()
	if register.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(register.Body)
		t.Fatalf("register status = %d, body %s", register.StatusCode, body)
	}
	raw, err := os.ReadFile(registrationPath)
	if err != nil || !bytes.Contains(raw, []byte("domain registered.example  # registered-by "+identity)) {
		t.Fatalf("registration file = %q, %v", raw, err)
	}
}
