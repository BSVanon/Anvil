package api

import (
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestEnabledReleaseFeaturesKeepCredentialsNarrow(t *testing.T) {
	srv, certificateWallet, registrationPath := certificateTestServer(t)
	srv.certificateGate.RequireSender = true
	identityResult, err := certificateWallet.GetPublicKey(t.Context(), wallet.GetPublicKeyArgs{IdentityKey: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	certificateIdentity := hex.EncodeToString(identityResult.PublicKey.Compressed())
	peer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    certificateWallet,
		Transport: newCertificateHTTPTransport(t, newPipeHTTPClient(t, srv.Handler())),
	})
	listed := fetchWithCertificatePeer(t, peer, "/listMessages", `{"messageBox":"inbox"}`)
	listed.Body.Close()
	if listed.StatusCode != http.StatusOK || !srv.certificateGate.Gate.Admitted(t.Context(), certificateIdentity) {
		t.Fatalf("certificate admission = %d, admitted=%v", listed.StatusCode, srv.certificateGate.Gate.Admitted(t.Context(), certificateIdentity))
	}
	registered := fetchWithCertificatePeer(t, peer, "/gateway/sites", `{"domain":"registered.example"}`)
	registered.Body.Close()
	if registered.StatusCode != http.StatusCreated {
		t.Fatalf("certificate registration = %d", registered.StatusCode)
	}
	if raw, err := os.ReadFile(registrationPath); err != nil || !strings.Contains(string(raw), "registered.example") {
		t.Fatalf("registration file = %q, %v", raw, err)
	}

	payments := newBRC121Fix(t, 100)
	resolver := NewTopicMonetizationResolver(srv.envelopeStore)
	payments.pg.resolver = resolver
	payments.pg.allowPassthrough = true
	payments.pg.allowSplit = true
	payments.pg.maxAppPriceSats = 10_000
	srv.paymentGate = payments.pg
	srv.tokenGate = NewTokenGate(resolver, true)

	const paidTopic = "release:paid"
	const tokenTopic = "release:token"
	const privateTopic = "release:private"
	const privateMarker = "release-private-marker"
	seedEnvelopeAt(t, srv.envelopeStore, paidTopic, `{"public":"paid"}`, time.Now().Unix(), passthrough(appPayeeScript(), 7))
	tokenKey, _ := ec.NewPrivateKey()
	seedEnvelopeAt(t, srv.envelopeStore, tokenTopic, `{"public":"token"}`, time.Now().Unix(), tokenModel(tokenKey))
	seedEnvelopeAt(t, srv.envelopeStore, privateTopic, `{"public":"plain"}`, time.Now().Unix(), nil)
	for _, topic := range []string{privateTopic, tokenTopic} {
		srv.envelopeStore.StoreEphemeralDirect(&envelope.Envelope{
			Type: "data", Topic: topic, Payload: privateMarker, Pubkey: propertyPrivatePubkey,
			Signature: "3045022100abcd", TTL: 60, Timestamp: time.Now().Unix() + 1, Private: true,
		})
	}
	rebuildRoutes(srv)

	priced := getWithHeaders(srv, "/data?topic="+paidTopic, nil)
	if priced.Code != http.StatusPaymentRequired {
		t.Fatalf("app-priced topic was not priced: %d %s", priced.Code, priced.Body.String())
	}
	payer := getWithHeaders(srv, "/data?topic="+privateTopic, payments.payment(t, 100, brc121Pay{}))
	if strings.Contains(payer.Body.String(), privateMarker) {
		t.Fatalf("payer received private envelope: %s", payer.Body.String())
	}
	appToken := getWithHeaders(srv, "/data?topic="+tokenTopic, map[string]string{"X-App-Token": mintAppToken(tokenKey, tokenTopic)})
	if appToken.Code != http.StatusOK || strings.Contains(appToken.Body.String(), privateMarker) || !strings.Contains(appToken.Body.String(), `\"token\"`) {
		t.Fatalf("app token response = %d %s", appToken.Code, appToken.Body.String())
	}
	certificateOnly := getWithHeaders(srv, "/data?topic="+privateTopic, nil)
	if !srv.certificateGate.Gate.Admitted(t.Context(), certificateIdentity) || certificateOnly.Code != http.StatusPaymentRequired || strings.Contains(certificateOnly.Body.String(), privateMarker) {
		t.Fatalf("certificate admission stood in for payment: admitted=%v, response=%d %s", srv.certificateGate.Gate.Admitted(t.Context(), certificateIdentity), certificateOnly.Code, certificateOnly.Body.String())
	}
	operator := getWithHeaders(srv, "/data?topic="+privateTopic, map[string]string{"Authorization": "Bearer test-operator-token"})
	if operator.Code != http.StatusOK || !strings.Contains(operator.Body.String(), privateMarker) {
		t.Fatalf("operator did not receive private envelope: %d %s", operator.Code, operator.Body.String())
	}

	sseBody := privateSSEBody(t, srv, privateTopic, payments.payment(t, 100, brc121Pay{}), false)
	if strings.Contains(sseBody, propertyPrivateSecret) {
		t.Fatalf("payer SSE received private envelope: %s", sseBody)
	}

	payerIdentity := hex.EncodeToString(payments.payer.identity.PubKey().Compressed())
	if srv.senderCertificateAllowed(t.Context(), payerIdentity) {
		t.Fatal("payment identity was treated as certificate-admitted")
	}
	paymentOnly := serveRouteCase(srv, pricedRouteCase{
		method: http.MethodPost, path: "/sendMessage",
		body: []byte(`{"recipient":"` + payerIdentity + `","messageBox":"box","body":"hello"}`),
	}, payments.payment(t, 100, brc121Pay{}))
	if paymentOnly.Code == http.StatusOK {
		t.Fatalf("payment stood in for BRC-31/certificate admission: %d %s", paymentOnly.Code, paymentOnly.Body.String())
	}
}
