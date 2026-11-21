package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/gateway"
	"github.com/bsv-blockchain/go-bsv-middleware/pkg/middleware"
	"github.com/bsv-blockchain/go-sdk/auth"
	"github.com/bsv-blockchain/go-sdk/auth/transports"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func offPropertyPeer(t *testing.T, handler http.Handler, clientWallet wallet.Interface) *auth.Peer {
	t.Helper()
	transport, err := transports.NewSimplifiedHTTPTransport(&transports.SimplifiedHTTPTransportOptions{
		BaseURL: "http://anvil.test", Client: newPipeHTTPClient(t, handler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth.NewPeer(&auth.PeerOptions{Wallet: clientWallet, Transport: transport})
}

func offPropertyPost(t *testing.T, peer *auth.Peer, path, body string) map[string]any {
	t.Helper()
	response := fetchWithCertificatePeer(t, peer, path, body)
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d, body %s", path, response.StatusCode, raw)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestCertificateSwitchesOffPreserveMessagebox(t *testing.T) {
	for _, gatePresent := range []bool{false, true} {
		for _, gatewayMode := range []bool{false, true} {
			name := "policy_absent"
			if gatePresent {
				name = "policy_present"
			}
			if gatewayMode {
				name += "/gateway"
			} else {
				name += "/standard"
			}
			t.Run(name, func(t *testing.T) {
				var admission func(wallet.Interface) CertificateAdmission
				if gatePresent {
					admission = func(wallet.Interface) CertificateAdmission {
						return CertificateAdmission{Gate: apiCertificateGate(t, mustPrivateKey(t))}
					}
				}
				srv, _ := buildTestServerBRC31(t, admission)
				var options middleware.AuthMiddlewareConfig
				for _, option := range srv.certificateAuthOptions() {
					option(&options)
				}
				if options.CertificatesToRequest != nil || options.OnCertificatesReceived != nil {
					t.Fatal("disabled uses requested certificates")
				}

				var handler http.Handler = srv.Handler()
				if gatewayMode {
					handler = &gateway.Router{API: handler, APIHost: "anvil.test"}
				}
				_, identity, clientWallet := newKeyWallet(t)
				peer := offPropertyPeer(t, handler, clientWallet)
				sent := offPropertyPost(t, peer, "/sendMessage", `{"recipient":"`+identity+`","messageBox":"box","body":"hello"}`)
				messageID, _ := sent["messageId"].(string)
				if messageID == "" {
					t.Fatalf("send response has no message ID: %#v", sent)
				}
				listed := offPropertyPost(t, peer, "/listMessages", `{"messageBox":"box"}`)
				if messages, _ := listed["messages"].([]any); len(messages) != 1 {
					t.Fatalf("list response = %#v", listed)
				}
				offPropertyPost(t, peer, "/acknowledgeMessage", `{"messageIds":["`+messageID+`"]}`)
				session := offPropertyPost(t, peer, "/messages/session", `{}`)
				token, _ := session["token"].(string)
				if token == "" {
					t.Fatalf("session response = %#v", session)
				}

				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				req := httptest.NewRequest(http.MethodGet, "/messages/subscribe?messageBox=box&token="+token, nil).WithContext(ctx)
				req.Host = "anvil.test"
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, req)
				if recorder.Code != http.StatusOK {
					t.Fatalf("subscribe status = %d, body %s", recorder.Code, recorder.Body.String())
				}
			})
		}
	}
}
