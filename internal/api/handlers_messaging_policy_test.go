package api

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/messaging"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
)

// stubHomeResolverAPI is a fixed-answer messaging.HomeResolver for
// decision 3's API-send table tests, below.
type stubHomeResolverAPI struct{ state messaging.HomeState }

func (s stubHomeResolverAPI) Resolve(string) (messaging.Resolution, error) {
	return messaging.Resolution{State: s.state}, nil
}

func apiTTLPtr(v int64) *int64 { return &v }
func apiBoolPtr(v bool) *bool  { return &v }

// TestSendHomeAware is decision 3's API-send table test: Home stores and
// never forwards; Unadvertised stores and forwards (today's behaviour).
func TestSendHomeAware(t *testing.T) {
	cases := []struct {
		name        string
		state       messaging.HomeState
		wantForward bool
	}{
		{"home never forwards", messaging.Home, false},
		{"unadvertised forwards", messaging.Unadvertised, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := messageHandlerServer(t, messaging.Options{})
			srv.forwardCopyTTLSeconds = apiTTLPtr(86400)
			srv.homeResolver = stubHomeResolverAPI{state: c.state}
			_, sender, _ := newKeyWallet(t)
			_, recipient, _ := newKeyWallet(t)
			msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "hi"}

			id, forward, err := srv.sendHomeAware(msg)
			if err != nil || id == "" {
				t.Fatalf("sendHomeAware = %q, %v", id, err)
			}
			if forward != c.wantForward {
				t.Fatalf("forward = %v, want %v", forward, c.wantForward)
			}
			msgs, err := srv.msgStore.List(recipient, "box")
			if err != nil || len(msgs) != 1 {
				t.Fatalf("expected the message stored either way: msgs=%+v err=%v", msgs, err)
			}
		})
	}
}

// TestSendHomeAwareElsewhereForwardCopyTTLZero covers the "Elsewhere"
// row with forward_copy_ttl=0: forwarded, never stored.
func TestSendHomeAwareElsewhereForwardCopyTTLZero(t *testing.T) {
	srv, _ := messageHandlerServer(t, messaging.Options{})
	srv.forwardCopyTTLSeconds = apiTTLPtr(0)
	srv.homeResolver = stubHomeResolverAPI{state: messaging.Elsewhere}
	_, sender, _ := newKeyWallet(t)
	_, recipient, _ := newKeyWallet(t)
	msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "hi"}

	id, forward, err := srv.sendHomeAware(msg)
	if err != nil || id == "" {
		t.Fatalf("sendHomeAware = %q, %v", id, err)
	}
	if !forward {
		t.Fatal("Elsewhere must still forward even when forward_copy_ttl=0")
	}
	msgs, err := srv.msgStore.List(recipient, "box")
	if err != nil || len(msgs) != 0 {
		t.Fatalf("expected nothing stored: msgs=%+v err=%v", msgs, err)
	}
}

// TestSendHomeAwareLegacyWhenForwardCopyTTLUnset confirms the "decisions
// 2/3 never wired up" fallback reproduces the exact pre-brick behaviour:
// store at ttl_seconds, always forward.
func TestSendHomeAwareLegacyWhenForwardCopyTTLUnset(t *testing.T) {
	srv, _ := messageHandlerServer(t, messaging.Options{})
	// forwardCopyTTLSeconds and homeResolver both left nil/unset.
	_, sender, _ := newKeyWallet(t)
	_, recipient, _ := newKeyWallet(t)
	msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "hi"}

	id, forward, err := srv.sendHomeAware(msg)
	if err != nil || id == "" {
		t.Fatalf("sendHomeAware = %q, %v", id, err)
	}
	if !forward {
		t.Fatal("the unwired legacy path must always forward, as before this brick")
	}
	msgs, err := srv.msgStore.List(recipient, "box")
	if err != nil || len(msgs) != 1 {
		t.Fatalf("expected the message stored: msgs=%+v err=%v", msgs, err)
	}
}

// TestHandleSendMessageHomeRealEndToEnd is the HTTP-handler-level version
// of decision 3's "no forward when Home" row, using a real connected
// mesh peer (mirroring internal/gossip's own end-to-end forward_peers
// test) rather than just the sendHomeAware unit tests above, so the
// mutation check ("drop the Home check on the API path, so forwards
// resume") has a test at the actual boundary it names.
func TestHandleSendMessageHomeRealEndToEnd(t *testing.T) {
	hubDir, err := os.MkdirTemp("", "anvil-home-e2e-hub-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(hubDir) })
	hubEnv, err := envelope.NewStore(hubDir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hubEnv.Close() })

	hubKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	gossipHub := gossip.NewManager(gossip.ManagerConfig{
		Wallet:         sdkwallet.NewTestWalletForRandomKey(t),
		Store:          hubEnv,
		LocalInterests: []string{""},
		MaxSeen:        100,
		IdentityKey:    hubKey,
	})
	t.Cleanup(func() { gossipHub.Stop() })
	ts := httptest.NewServer(gossipHub.MeshHandler())
	t.Cleanup(ts.Close)
	wsURL := "ws" + ts.URL[len("http"):]

	peerDir, err := os.MkdirTemp("", "anvil-home-e2e-peer-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(peerDir) })
	peerEnv, err := envelope.NewStore(peerDir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerEnv.Close() })
	peerMsgStore, err := messaging.NewStore(t.TempDir(), messaging.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peerMsgStore.Close() })
	peerMgr := gossip.NewManager(gossip.ManagerConfig{
		Wallet:         sdkwallet.NewTestWalletForRandomKey(t),
		Store:          peerEnv,
		LocalInterests: []string{""},
		MaxSeen:        100,
	})
	peerMgr.SetMsgStore(peerMsgStore)
	t.Cleanup(func() { peerMgr.Stop() })
	if err := peerMgr.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if gossipHub.PeerCount() != 1 {
		t.Fatalf("expected 1 peer on hub, got %d", gossipHub.PeerCount())
	}

	srv, _ := messageHandlerServer(t, messaging.Options{})
	// The v2 message ID binds to the minting origin node (s.identityPub,
	// passed to Store.Send as originNode) and is verified by the
	// receiving peer against the forward's signing identity
	// (gossipHub's IdentityKey) — they must be the same identity for a
	// real forward to verify.
	srv.identityPub = hex.EncodeToString(hubKey.PubKey().Compressed())
	srv.gossipMgr = gossipHub
	srv.forwardCopyTTLSeconds = apiTTLPtr(86400)

	_, homeRecipient, _ := newKeyWallet(t)
	_, elsewhereRecipient, _ := newKeyWallet(t)
	srv.homeResolver = fixedStatesHomeResolver{
		homeRecipient:      homeRecipient,
		unadvertisedState:  messaging.Unadvertised,
		elsewhereRecipient: elsewhereRecipient,
	}

	// Home: must be stored locally and never reach the peer.
	if response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": homeRecipient, "messageBox": "box", "body": "home copy",
	}); response.Code != http.StatusOK {
		t.Fatalf("home send = %d, %v", response.Code, body)
	}

	// Unadvertised: must forward, and the peer should receive and store it.
	if response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": elsewhereRecipient, "messageBox": "box", "body": "unadvertised copy",
	}); response.Code != http.StatusOK {
		t.Fatalf("unadvertised send = %d, %v", response.Code, body)
	}

	time.Sleep(600 * time.Millisecond)

	if peerMsgStore.Count() != 1 {
		t.Fatalf("peer store count = %d, want 1 (only the unadvertised-recipient forward)", peerMsgStore.Count())
	}
	if msgs, _ := peerMsgStore.List(homeRecipient, "box"); len(msgs) != 0 {
		t.Fatalf("the Home-recipient message must never reach the peer: %+v", msgs)
	}
}

// fixedStatesHomeResolver answers Home for one specific recipient and
// Unadvertised for everyone else — enough to drive the end-to-end test
// above without a real ls_messagebox-backed resolver.
type fixedStatesHomeResolver struct {
	homeRecipient      string
	unadvertisedState  messaging.HomeState
	elsewhereRecipient string
}

func (f fixedStatesHomeResolver) Resolve(recipient string) (messaging.Resolution, error) {
	if recipient == f.homeRecipient {
		return messaging.Resolution{State: messaging.Home}, nil
	}
	return messaging.Resolution{State: f.unadvertisedState}, nil
}

// TestOperatorBoxAllowed is a direct unit test of decision 5's
// predicate: naming nothing or the node's own box is always allowed;
// naming another box depends on operator_reads_all_boxes.
func TestOperatorBoxAllowed(t *testing.T) {
	srv, nodeHex := messageHandlerServer(t, messaging.Options{})
	_, other, _ := newKeyWallet(t)

	if !srv.operatorBoxAllowed("") || !srv.operatorBoxAllowed(nodeHex) {
		t.Fatal("naming nothing or the node's own box must always be allowed")
	}
	if !srv.operatorBoxAllowed(other) {
		t.Fatal("default (operator_reads_all_boxes unset) must allow naming another box")
	}

	srv.operatorReadsAllBoxes = apiBoolPtr(false)
	if !srv.operatorBoxAllowed("") || !srv.operatorBoxAllowed(nodeHex) {
		t.Fatal("the node's own box must remain allowed even when the switch is false")
	}
	if srv.operatorBoxAllowed(other) {
		t.Fatal("naming another box must be denied when operator_reads_all_boxes is false")
	}

	srv.operatorReadsAllBoxes = apiBoolPtr(true)
	if !srv.operatorBoxAllowed(other) {
		t.Fatal("naming another box must be allowed when the switch is explicitly true")
	}
}

// TestScopedRecipientOperatorSwitch exercises decision 5's required
// test: "listing or acknowledging another box gets a 403 when the
// switch is false, and nothing changes when it is true."
func TestScopedRecipientOperatorSwitch(t *testing.T) {
	srv, nodeHex := messageHandlerServer(t, messaging.Options{})
	_, other, _ := newKeyWallet(t)
	operatorCaller := messageCaller{identityHex: nodeHex, scoped: false}

	for _, switchVal := range []*bool{nil, apiBoolPtr(true)} {
		srv.operatorReadsAllBoxes = switchVal
		w := httptest.NewRecorder()
		got, ok := srv.scopedRecipient(w, operatorCaller, other)
		if !ok || got != other {
			t.Fatalf("switch=%v: naming another box should be unaffected: got=%q ok=%v", switchVal, got, ok)
		}
	}

	srv.operatorReadsAllBoxes = apiBoolPtr(false)
	w := httptest.NewRecorder()
	got, ok := srv.scopedRecipient(w, operatorCaller, other)
	if ok || got != "" || w.Code != http.StatusForbidden {
		t.Fatalf("switch=false: naming another box should 403: got=%q ok=%v code=%d", got, ok, w.Code)
	}

	// The node's own box, and no recipient at all, remain allowed.
	for _, body := range []string{"", nodeHex} {
		w = httptest.NewRecorder()
		got, ok = srv.scopedRecipient(w, operatorCaller, body)
		if !ok || got != nodeHex {
			t.Fatalf("switch=false, body=%q: own box should remain allowed: got=%q ok=%v", body, got, ok)
		}
	}

	// A BRC-31-scoped caller is always restricted to its own identity,
	// regardless of the switch.
	scopedCaller := messageCaller{identityHex: other, scoped: true}
	w = httptest.NewRecorder()
	got, ok = srv.scopedRecipient(w, scopedCaller, nodeHex)
	if !ok || got != other {
		t.Fatalf("a scoped caller must stay scoped to itself regardless of body/switch: got=%q ok=%v", got, ok)
	}
}

// TestHandleMessageSubscribeOperatorSwitch is decision 5's SSE path:
// the operator fallback's ?recipient= query override is gated the same
// way as scopedRecipient.
//
// Uses a real HTTP server (not httptest.NewRecorder from a second
// goroutine): the 200 cases enter handleMessageSubscribe's streaming
// loop, which keeps writing to the ResponseWriter until the request
// context is cancelled — reading a shared httptest.ResponseRecorder's
// fields from the test goroutine while that loop runs concurrently is a
// data race. A real server lets the http.Client/transport own that
// synchronization instead.
func TestHandleMessageSubscribeOperatorSwitch(t *testing.T) {
	srv := testServerWithMsgStore(t)
	_, other, _ := newKeyWallet(t)
	ts := httptest.NewServer(http.HandlerFunc(srv.handleMessageSubscribe))
	t.Cleanup(ts.Close)

	get := func(recipient string) int {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		u := ts.URL + "/messages/subscribe?messageBox=box&token=" + srv.authToken
		if recipient != "" {
			u += "&recipient=" + url.QueryEscape(recipient)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	srv.operatorReadsAllBoxes = apiBoolPtr(false)
	if code := get(other); code != http.StatusForbidden {
		t.Fatalf("switch=false, other recipient: code = %d", code)
	}
	if code := get(srv.identityPub); code != http.StatusOK {
		t.Fatalf("switch=false, own recipient: code = %d", code)
	}
	if code := get(""); code != http.StatusOK {
		t.Fatalf("switch=false, no recipient: code = %d", code)
	}
}
