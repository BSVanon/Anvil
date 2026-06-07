package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authhttp "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"

	"log/slog"
)

// newKeyWallet returns a fresh identity: private key, compressed-pubkey hex, and
// a full go-sdk wallet.Interface for BRC-31 mutual auth (client or server side).
func newKeyWallet(t *testing.T) (*ec.PrivateKey, string, sdkwallet.Interface) {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	w, err := sdkwallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, hex.EncodeToString(priv.PubKey().Compressed()), w
}

// testServerBRC31 builds an API server whose messagebox routes are served behind
// canonical BRC-31 mutual auth (Wallet set), with a real on-disk message store.
// Returns the server, an httptest server, the node identity hex, and the node
// (server) wallet identity.
func testServerBRC31(t *testing.T) (*Server, *httptest.Server, string) {
	t.Helper()
	hdir := t.TempDir()
	hs, err := headers.NewTestStore(hdir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	ps, err := spv.NewProofStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })
	es, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { es.Close() })
	ms, err := messaging.NewStore(t.TempDir(), 86400)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })

	logger := slog.Default()
	mp := txrelay.NewMempool()
	broadcaster := txrelay.NewBroadcaster(mp, nil, logger)

	_, nodeHex, nodeWallet := newKeyWallet(t)

	srv := NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es,
		Validator:   spv.NewValidator(hs),
		Broadcaster: broadcaster,
		AuthToken:   "test-operator-token",
		IdentityPub: nodeHex,
		MsgStore:    ms,
		Wallet:      nodeWallet,
		Logger:      logger,
	})
	if !srv.messageboxBRC31 {
		t.Fatal("expected messageboxBRC31 to be enabled when Wallet is set")
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts, nodeHex
}

// authPost performs a BRC-31-authenticated POST via the go-sdk AuthFetch client
// (the same handshake @bsv/sdk AuthFetch performs in the browser) and returns
// the decoded JSON body + status.
func authPost(t *testing.T, w sdkwallet.Interface, url string, payload any) (map[string]any, int) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	client := authhttp.New(w)
	resp, err := client.Fetch(context.Background(), url, &authhttp.SimplifiedFetchRequestOptions{
		Method:  "POST",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    body,
	})
	if err != nil {
		t.Fatalf("AuthFetch %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, resp.StatusCode
}

// TestMessagebox_BRC31_RoundTrip proves the end-to-end canonical path: a client
// sends a message authenticated by its OWN identity key (no operator secret),
// and the recipient — authenticating as itself — reads it back. The stored
// sender must be the client's identity, not the node's.
func TestMessagebox_BRC31_RoundTrip(t *testing.T) {
	_, ts, nodeHex := testServerBRC31(t)

	_, aliceHex, aliceW := newKeyWallet(t)
	_, bobHex, bobW := newKeyWallet(t)

	// Alice sends to Bob's inbox, authenticated as Alice.
	out, code := authPost(t, aliceW, ts.URL+"/sendMessage", map[string]string{
		"recipient": bobHex, "messageBox": "dex.swap", "body": "offer-123",
	})
	if code != http.StatusOK {
		t.Fatalf("sendMessage: status %d (%v)", code, out)
	}

	// Bob lists his inbox, authenticated as Bob. Scoped strictly to Bob.
	out, code = authPost(t, bobW, ts.URL+"/listMessages", map[string]string{
		"messageBox": "dex.swap",
	})
	if code != http.StatusOK {
		t.Fatalf("listMessages: status %d (%v)", code, out)
	}
	msgs, _ := out["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message in Bob's inbox, got %d (%v)", len(msgs), out)
	}
	m := msgs[0].(map[string]any)
	if m["sender"] != aliceHex {
		t.Errorf("sender must be Alice's identity %s, got %v (node is %s)", aliceHex, m["sender"], nodeHex)
	}
	if m["body"] != "offer-123" {
		t.Errorf("body mismatch: %v", m["body"])
	}
}

// TestMessagebox_BRC31_ListScopedToCaller proves list is strictly scoped to the
// authenticated identity — a caller cannot read another identity's inbox even by
// supplying a different recipient in the body.
func TestMessagebox_BRC31_ListScopedToCaller(t *testing.T) {
	_, ts, _ := testServerBRC31(t)

	_, aliceHex, aliceW := newKeyWallet(t)
	_, bobHex, _ := newKeyWallet(t)

	// Alice sends to Bob.
	if _, code := authPost(t, aliceW, ts.URL+"/sendMessage", map[string]string{
		"recipient": bobHex, "messageBox": "dex.swap", "body": "for-bob",
	}); code != http.StatusOK {
		t.Fatalf("send: %d", code)
	}

	// Alice tries to read Bob's inbox by putting Bob's pubkey in the body.
	// Must be ignored — Alice is scoped to her own (empty) inbox.
	out, code := authPost(t, aliceW, ts.URL+"/listMessages", map[string]string{
		"recipient": bobHex, "messageBox": "dex.swap",
	})
	if code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if msgs, _ := out["messages"].([]any); len(msgs) != 0 {
		t.Errorf("Alice must NOT read Bob's inbox via body recipient; got %d messages", len(msgs))
	}
	_ = aliceHex
}

// TestMessagebox_SessionTokenRoundTrip proves the 2a SSE bootstrap: a client
// mints a per-identity session token via BRC-31, and that token resolves to the
// client's identity in the server's session store (never the operator secret).
func TestMessagebox_SessionTokenRoundTrip(t *testing.T) {
	srv, ts, _ := testServerBRC31(t)
	_, aliceHex, aliceW := newKeyWallet(t)

	out, code := authPost(t, aliceW, ts.URL+"/messages/session", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("mint session: status %d (%v)", code, out)
	}
	tok, _ := out["token"].(string)
	if tok == "" {
		t.Fatalf("no token returned: %v", out)
	}
	id, ok := srv.msgSessions.resolve(tok, time.Now())
	if !ok || id != aliceHex {
		t.Fatalf("session token must resolve to Alice (%s), got id=%q ok=%v", aliceHex, id, ok)
	}
	// A bogus token must not resolve.
	if _, ok := srv.msgSessions.resolve("deadbeef", time.Now()); ok {
		t.Error("bogus session token must not resolve")
	}
}

// TestMessagebox_OperatorFallback proves backward compatibility: the operator
// token still works for node tooling (no BRC-31), with the node as sender.
func TestMessagebox_OperatorFallback(t *testing.T) {
	srv, ts, nodeHex := testServerBRC31(t)
	_, _, bobW := newKeyWallet(t)
	_ = bobW

	// Plain HTTP with operator bearer token — no BRC-31 handshake.
	body, _ := json.Marshal(map[string]string{"recipient": nodeHex, "messageBox": "ops", "body": "hi"})
	req, _ := http.NewRequest("POST", ts.URL+"/sendMessage", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-operator-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator send: status %d", resp.StatusCode)
	}

	// No auth at all → 401.
	req2, _ := http.NewRequest("POST", ts.URL+"/sendMessage", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated send must be 401, got %d", resp2.StatusCode)
	}
	_ = srv
}

// TestSessionTokenStore covers mint/resolve/expiry/eviction of the SSE session
// token store directly (deterministic clock).
func TestSessionTokenStore(t *testing.T) {
	store := newSessionTokenStore(time.Minute)
	base := time.Unix(1_700_000_000, 0)

	tok, exp, err := store.mint("identityA", base)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.After(base) {
		t.Fatal("expiry must be after mint time")
	}
	if id, ok := store.resolve(tok, base.Add(30*time.Second)); !ok || id != "identityA" {
		t.Fatalf("token should resolve to identityA, got %q ok=%v", id, ok)
	}
	// Expired token must not resolve.
	if _, ok := store.resolve(tok, base.Add(2*time.Minute)); ok {
		t.Error("expired token must not resolve")
	}
	// Empty + unknown tokens never resolve.
	if _, ok := store.resolve("", base); ok {
		t.Error("empty token must not resolve")
	}
	if _, ok := store.resolve("nope", base); ok {
		t.Error("unknown token must not resolve")
	}
}
