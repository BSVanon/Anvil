package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/certgate"
	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-sdk/auth"
	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-sdk/wallet/testcertificates"
)

func signedHTTPPrivateHome(t *testing.T, member *ec.PrivateKey, homes []string, issuedAt int64) messaging.PrivateHomeRecord {
	t.Helper()
	record := messaging.PrivateHomeRecord{
		Kind: messaging.PrivateHomeClaim, Member: hex.EncodeToString(member.PubKey().Compressed()), Homes: homes,
		IssuedAt: issuedAt, ExpiresAt: issuedAt/1000 + 3600,
	}
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypePrivateKey, PrivateKey: member})
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID: wallet.Protocol{SecurityLevel: 1, Protocol: "anvil private home"}, KeyID: "1",
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		},
		Data: messaging.PrivateHomeCanonicalBytes(record),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	record.Signature = hex.EncodeToString(result.Signature.Serialize())
	return record
}

func privateHomeHTTPServer(t *testing.T, admission CertificateAdmission, homes []string) (*Server, *http.Client) {
	t.Helper()
	srv, _ := buildTestServerBRC31(t, func(wallet.Interface) CertificateAdmission { return admission }, func(store *messaging.Store, node string) MessagingPolicy {
		allowed := append(append([]string(nil), homes...), node)
		registry := messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
			MaxMembers: 10, MaxTTL: 3600, AllowedHomes: allowed,
		})
		return MessagingPolicy{PrivateHomes: registry, Home: messaging.NewPrivateHomeResolver(registry, node, messaging.AlwaysUnadvertised)}
	})
	return srv, newPipeHTTPClient(t, srv.Handler())
}

func authPrivateHome(t *testing.T, walletClient wallet.Interface, httpClient *http.Client, method, url string, body any) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	response, err := authhttp.New(walletClient, authhttp.WithHttpClient(httpClient)).Fetch(context.Background(), url, &authhttp.SimplifiedFetchRequestOptions{
		Method: method, Headers: map[string]string{"Content-Type": "application/json"}, Body: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	var decoded map[string]any
	_ = json.Unmarshal(data, &decoded)
	return response.StatusCode, decoded
}

func TestPrivateHomeHTTPScopesClaimsAndRejectsStaleRecords(t *testing.T) {
	memberKey, memberHex, memberWallet := newKeyWallet(t)
	otherKey, _, otherWallet := newKeyWallet(t)
	homeKey, _, _ := newKeyWallet(t)
	home := hex.EncodeToString(homeKey.PubKey().Compressed())
	_, httpClient := privateHomeHTTPServer(t, CertificateAdmission{}, []string{home})
	now := time.Now().UnixMilli()
	claim := signedHTTPPrivateHome(t, memberKey, []string{home}, now)

	code, body := authPrivateHome(t, otherWallet, httpClient, http.MethodPost, "http://anvil.test/messages/home", map[string]any{"claim": claim})
	if code != http.StatusForbidden || body["code"] != "ERR_CLAIM_MEMBER_MISMATCH" {
		t.Fatalf("member mismatch = %d, %#v", code, body)
	}
	code, body = authPrivateHome(t, memberWallet, httpClient, http.MethodPost, "http://anvil.test/messages/home", map[string]any{"claim": claim})
	if code != http.StatusOK {
		t.Fatalf("claim = %d, %#v", code, body)
	}
	code, body = authPrivateHome(t, memberWallet, httpClient, http.MethodPost, "http://anvil.test/messages/home", map[string]any{"claim": claim})
	if code != http.StatusConflict || body["code"] != "ERR_CLAIM_STALE" {
		t.Fatalf("stale claim = %d, %#v", code, body)
	}
	code, body = authPrivateHome(t, memberWallet, httpClient, http.MethodGet, "http://anvil.test/messages/home", nil)
	if code != http.StatusOK || body["claim"].(map[string]any)["member"] != memberHex {
		t.Fatalf("own claim = %d, %#v", code, body)
	}
	code, _ = authPrivateHome(t, otherWallet, httpClient, http.MethodGet, "http://anvil.test/messages/home", nil)
	if code != http.StatusNotFound {
		t.Fatalf("other caller read claim: %d", code)
	}
	_ = otherKey
}

func TestPrivateHomeHTTPOperatorTokenIsRefused(t *testing.T) {
	member, _, _ := newKeyWallet(t)
	home, _, _ := newKeyWallet(t)
	homeHex := hex.EncodeToString(home.PubKey().Compressed())
	_, httpClient := privateHomeHTTPServer(t, CertificateAdmission{}, []string{homeHex})
	claim := signedHTTPPrivateHome(t, member, []string{homeHex}, time.Now().UnixMilli())
	raw, _ := json.Marshal(map[string]any{"claim": claim})
	request, _ := http.NewRequest(http.MethodPost, "http://anvil.test/messages/home", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer test-operator-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("operator token status = %d", response.StatusCode)
	}
}

func TestPrivateHomeHTTPRejectsConnectedIncompatibleGateway(t *testing.T) {
	member, _, memberWallet := newKeyWallet(t)
	home, _, _ := newKeyWallet(t)
	homeHex := hex.EncodeToString(home.PubKey().Compressed())
	server, httpClient := privateHomeHTTPServer(t, CertificateAdmission{}, []string{homeHex})
	server.messagingPolicy.PrivateHomeCompatible = func([]string) bool { return false }
	claim := signedHTTPPrivateHome(t, member, []string{homeHex}, time.Now().UnixMilli())
	invalid := claim
	invalid.Signature = "00" + invalid.Signature[2:]
	code, body := authPrivateHome(t, memberWallet, httpClient, http.MethodPost, "http://anvil.test/messages/home", map[string]any{"claim": invalid})
	if code != http.StatusBadRequest || body["code"] != "ERR_INVALID_CLAIM" {
		t.Fatalf("invalid incompatible claim = %d, %#v", code, body)
	}
	code, body = authPrivateHome(t, memberWallet, httpClient, http.MethodPost, "http://anvil.test/messages/home", map[string]any{"claim": claim})
	if code != http.StatusConflict || body["code"] != "ERR_HOME_INCOMPATIBLE" {
		t.Fatalf("incompatible home = %d, %#v", code, body)
	}
}

func TestPrivateHomeHTTPCertificateAdmissionUsesRegistrationError(t *testing.T) {
	certifier, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	typeID, err := wallet.CertificateTypeFromString("private home membership")
	if err != nil {
		t.Fatal(err)
	}
	typeBase64 := base64.StdEncoding.EncodeToString(typeID.Bytes())
	member, memberHex, baseMemberWallet := newKeyWallet(t)
	certificateWallet := wallet.NewTestWallet(t, member)
	certificateManager := testcertificates.NewManager(t, certificateWallet)
	certificateManager.CertificateForTest().WithType("private home membership").WithFieldValue("role", "member").IssueWithCertifier(certifier)
	memberWallet := certificateClientWallet{Interface: baseMemberWallet, certificates: certificateWallet}
	home, _, _ := newKeyWallet(t)
	homeHex := hex.EncodeToString(home.PubKey().Compressed())
	var gate *certgate.Gate
	srv, _ := buildTestServerBRC31(t, func(nodeWallet wallet.Interface) CertificateAdmission {
		var gateErr error
		gate, gateErr = certgate.New(certgate.Config{
			Certifiers: []string{hex.EncodeToString(certifier.PubKey().Compressed())}, Types: []string{typeBase64},
			RevealFields: map[string][]string{typeBase64: {"role"}}, AllowUnrevocable: map[string]bool{typeBase64: true},
			RevocationCheck: "strict", Recheck: time.Hour, Wallet: nodeWallet, Watcher: apiCertWatcher{},
		})
		if gateErr != nil {
			t.Fatal(gateErr)
		}
		return CertificateAdmission{Gate: gate}
	}, func(store *messaging.Store, node string) MessagingPolicy {
		registry := messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
			MaxMembers: 10, MaxTTL: 3600, AllowedHomes: []string{homeHex, node},
		})
		return MessagingPolicy{PrivateHomes: registry, Home: messaging.NewPrivateHomeResolver(registry, node, messaging.AlwaysUnadvertised)}
	})
	transport := newCertificateHTTPTransport(t, newPipeHTTPClient(t, srv.Handler()))
	peer := auth.NewPeer(&auth.PeerOptions{Wallet: memberWallet, Transport: transport})

	claim := signedHTTPPrivateHome(t, member, []string{homeHex}, time.Now().UnixMilli())
	raw, _ := json.Marshal(map[string]any{"claim": claim})
	response := fetchWithCertificatePeer(t, peer, "/messages/home", string(raw))
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("admitted claim = %d, %s", response.StatusCode, body)
	}
	response.Body.Close()
	if !gate.Admitted(t.Context(), memberHex) {
		t.Fatal("certificate did not create an admission")
	}
	refusingGate, err := certgate.New(certgate.Config{
		Certifiers: []string{hex.EncodeToString(certifier.PubKey().Compressed())}, Types: []string{typeBase64},
		RevealFields: map[string][]string{typeBase64: {"role"}}, AllowUnrevocable: map[string]bool{typeBase64: true},
		RevocationCheck: "strict", Recheck: time.Hour, Watcher: apiCertWatcher{},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.certificateGate.Gate = refusingGate

	newer := signedHTTPPrivateHome(t, member, []string{homeHex}, claim.IssuedAt+1)
	raw, _ = json.Marshal(map[string]any{"claim": newer})
	response = fetchWithCertificatePeer(t, peer, "/messages/home", string(raw))
	defer response.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(response.Body).Decode(&body)
	if response.StatusCode != http.StatusForbidden || body["code"] != "ERR_CERTIFICATE_REQUIRED" {
		t.Fatalf("revoked admission = %d, %#v", response.StatusCode, body)
	}
}
