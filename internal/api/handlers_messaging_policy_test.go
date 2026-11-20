package api

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/messaging"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
)

// sendHomeAware's "API send" table (handlers_messaging.go):
// what happens when a client POSTs a message, for each HomeState the
// recipient resolves to. The operator read-all-boxes switch has its own
// tests in handlers_messaging_operator_test.go.

// stubHomeResolverAPI is a fixed-answer messaging.HomeResolver for
// the API-send table tests, below.
type stubHomeResolverAPI struct{ state messaging.HomeState }

func (s stubHomeResolverAPI) Resolve(string) (messaging.Resolution, error) {
	return messaging.Resolution{State: s.state}, nil
}

func apiTTLPtr(v int64) *int64 { return &v }
func apiBoolPtr(v bool) *bool  { return &v }

// TestSendHomeAware is the Home Rule's API-send table test: Home stores and
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
			srv.messagingPolicy.ForwardCopyTTLSeconds = apiTTLPtr(86400)
			srv.messagingPolicy.Home = stubHomeResolverAPI{state: c.state}
			_, sender, _ := newKeyWallet(t)
			_, recipient, _ := newKeyWallet(t)
			msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "hi"}

			id, forward, stored, err := srv.sendHomeAware(msg)
			if err != nil || id == "" {
				t.Fatalf("sendHomeAware = %q, %v", id, err)
			}
			if forward != c.wantForward {
				t.Fatalf("forward = %v, want %v", forward, c.wantForward)
			}
			if !stored {
				t.Fatal("expected stored=true: both Home and Unadvertised always store here")
			}
			msgs, err := srv.msgStore.List(recipient, "box")
			if err != nil || len(msgs) != 1 {
				t.Fatalf("expected the message stored either way: msgs=%+v err=%v", msgs, err)
			}
		})
	}
}

// TestHandleSendMessageUndeliveredReturns503 is a required guard: a
// message that lands nowhere — nothing stored at this node, AND the
// forward (when attempted) reaches zero peers — must not come back 200.
// Elsewhere with forward_copy_ttl=0 and no gossipMgr wired reproduces
// exactly this: sendHomeAware reports stored=false, and
// handleSendMessage never even tries ForwardMessage (gossipMgr is nil),
// so sentTo stays 0 too.
func TestHandleSendMessageUndeliveredReturns503(t *testing.T) {
	srv, _ := messageHandlerServer(t, messaging.Options{})
	srv.messagingPolicy.ForwardCopyTTLSeconds = apiTTLPtr(0)
	srv.messagingPolicy.Home = stubHomeResolverAPI{state: messaging.Elsewhere}
	// srv.gossipMgr is left nil: forward is skipped entirely, so a
	// nonzero ForwardMessage count can never mask the missing store.
	_, recipient, _ := newKeyWallet(t)

	response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": recipient, "messageBox": "box", "body": "hi",
	})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d: body=%v", response.Code, http.StatusServiceUnavailable, body)
	}
	if code, _ := body["code"].(string); code != "ERR_MESSAGE_UNDELIVERED" {
		t.Fatalf("code = %q, want ERR_MESSAGE_UNDELIVERED: body=%v", code, body)
	}
	if msgs, _ := srv.msgStore.List(recipient, "box"); len(msgs) != 0 {
		t.Fatalf("expected nothing stored, got %+v", msgs)
	}
}

// TestSendHomeAwareElsewhereForwardCopyTTLZero covers the "Elsewhere"
// row with forward_copy_ttl=0: forwarded, never stored.
func TestSendHomeAwareElsewhereForwardCopyTTLZero(t *testing.T) {
	srv, _ := messageHandlerServer(t, messaging.Options{})
	srv.messagingPolicy.ForwardCopyTTLSeconds = apiTTLPtr(0)
	srv.messagingPolicy.Home = stubHomeResolverAPI{state: messaging.Elsewhere}
	_, sender, _ := newKeyWallet(t)
	_, recipient, _ := newKeyWallet(t)
	msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "hi"}

	id, forward, stored, err := srv.sendHomeAware(msg)
	if err != nil || id == "" {
		t.Fatalf("sendHomeAware = %q, %v", id, err)
	}
	if !forward {
		t.Fatal("Elsewhere must still forward even when forward_copy_ttl=0")
	}
	if stored {
		t.Fatal("expected stored=false: the signal that this specific send landed only via the forward, not a local copy")
	}
	msgs, err := srv.msgStore.List(recipient, "box")
	if err != nil || len(msgs) != 0 {
		t.Fatalf("expected nothing stored: msgs=%+v err=%v", msgs, err)
	}
}

// TestSendHomeAwareElsewhereStoresAtForwardCopyTTLNotTTLSeconds covers a
// bug a review found: swapping forward_copy_ttl for the store's
// ttl_seconds at this call site (handlers_messaging.go's sendHomeAware
// Elsewhere row, ":128") survived because no existing test inspected
// the stored copy's actual expiry basis, only that a copy existed
// (TestSendHomeAwareElsewhereForwardCopyTTLZero, above, covers
// forward_copy_ttl=0, where there is nothing to store at all). ttl_seconds
// is set explicitly (604800) rather than relying on the store's internal
// default so this test does not depend on that constant staying put;
// forward_copy_ttl (86400) is deliberately far from it so the two bases
// are numerically distinguishable — see the gossip-side sibling test,
// internal/gossip/handlers_msg_policy_test.go's
// TestDeliverForwardNonHomeForwardCopyTTLUsedNotStoreTTLSeconds, for the
// same check on the other call site.
func TestSendHomeAwareElsewhereStoresAtForwardCopyTTLNotTTLSeconds(t *testing.T) {
	const ttlSeconds = int64(604800)
	const forwardCopyTTL = int64(86400)
	srv, _ := messageHandlerServer(t, messaging.Options{TTLSeconds: ttlSeconds})
	srv.messagingPolicy.ForwardCopyTTLSeconds = apiTTLPtr(forwardCopyTTL)
	srv.messagingPolicy.Home = stubHomeResolverAPI{state: messaging.Elsewhere}
	_, sender, _ := newKeyWallet(t)
	_, recipient, _ := newKeyWallet(t)
	msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "hi"}

	if _, _, stored, err := srv.sendHomeAware(msg); err != nil || !stored {
		t.Fatalf("sendHomeAware: stored=%v err=%v", stored, err)
	}
	msgs, err := srv.msgStore.List(recipient, "box")
	if err != nil || len(msgs) != 1 {
		t.Fatalf("expected 1 stored copy: msgs=%+v err=%v", msgs, err)
	}
	want := msgs[0].ReceivedAt + forwardCopyTTL - ttlSeconds
	if msgs[0].ExpiryBase != want {
		t.Fatalf("ExpiryBase = %d, want %d (forward_copy_ttl-based; the store's ttl_seconds-based value would wrongly give %d)",
			msgs[0].ExpiryBase, want, msgs[0].ReceivedAt)
	}
}

// TestSendHomeAwareLegacyWhenForwardCopyTTLUnset confirms the "never
// wired up" fallback reproduces the exact original behaviour:
// store at ttl_seconds, always forward.
func TestSendHomeAwareLegacyWhenForwardCopyTTLUnset(t *testing.T) {
	srv, _ := messageHandlerServer(t, messaging.Options{})
	// forwardCopyTTLSeconds and homeResolver both left nil/unset.
	_, sender, _ := newKeyWallet(t)
	_, recipient, _ := newKeyWallet(t)
	msg := &messaging.Message{Sender: sender, Recipient: recipient, MessageBox: "box", Body: "hi"}

	id, forward, stored, err := srv.sendHomeAware(msg)
	if err != nil || id == "" {
		t.Fatalf("sendHomeAware = %q, %v", id, err)
	}
	if !forward {
		t.Fatal("the unwired legacy path must always forward, as it always has")
	}
	if !stored {
		t.Fatal("expected stored=true: the legacy path always stores")
	}
	msgs, err := srv.msgStore.List(recipient, "box")
	if err != nil || len(msgs) != 1 {
		t.Fatalf("expected the message stored: msgs=%+v err=%v", msgs, err)
	}
}

// fixedStatesHomeResolver answers Home for one specific recipient and
// Unadvertised for everyone else — enough to drive the end-to-end test
// below without a real ls_messagebox-backed resolver.
type fixedStatesHomeResolver struct {
	homeRecipient      string
	unadvertisedState  messaging.HomeState
	elsewhereRecipient string
}

func (f fixedStatesHomeResolver) Resolve(recipient string) (messaging.Resolution, error) {
	switch recipient {
	case f.homeRecipient:
		return messaging.Resolution{State: messaging.Home}, nil
	case f.elsewhereRecipient:
		// This case used to be unreachable — recipient never matched
		// here, so elsewhereRecipient silently fell through to
		// unadvertisedState below, and the end-to-end test's "Elsewhere"
		// send was actually exercising Unadvertised the whole time.
		return messaging.Resolution{State: messaging.Elsewhere}, nil
	default:
		return messaging.Resolution{State: f.unadvertisedState}, nil
	}
}

// TestHandleSendMessageHomeRealEndToEnd is the HTTP-handler-level version
// of the Home Rule's "no forward when Home" row, using a real connected
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
	srv.messagingPolicy.ForwardCopyTTLSeconds = apiTTLPtr(86400)

	_, homeRecipient, _ := newKeyWallet(t)
	_, elsewhereRecipient, _ := newKeyWallet(t)
	_, unadvertisedRecipient, _ := newKeyWallet(t)
	srv.messagingPolicy.Home = fixedStatesHomeResolver{
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

	// Elsewhere, forward_copy_ttl>0 (a REAL Elsewhere case: before
	// the fix, fixedStatesHomeResolver never actually returned Elsewhere
	// for any recipient, so this send exercised Unadvertised under an
	// Elsewhere-sounding name): stored locally at the shorter TTL AND
	// forwarded.
	if response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": elsewhereRecipient, "messageBox": "box", "body": "elsewhere copy, ttl>0",
	}); response.Code != http.StatusOK {
		t.Fatalf("elsewhere send = %d, %v", response.Code, body)
	}

	// Unadvertised (a genuinely different, unnamed recipient): stored
	// locally AND forwarded — same observable outcome as the Elsewhere
	// case above, but through the resolver's default branch rather than
	// its explicit Elsewhere case.
	if response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": unadvertisedRecipient, "messageBox": "box", "body": "unadvertised copy",
	}); response.Code != http.StatusOK {
		t.Fatalf("unadvertised send = %d, %v", response.Code, body)
	}

	// Elsewhere again, now with forward_copy_ttl=0 (relay-only): this is
	// the one case that actually DISTINGUISHES Elsewhere from
	// Unadvertised — Unadvertised always stores regardless of TTL, so
	// this send would still show up in srv.msgStore under the
	// old resolver bug. Forwarded either way.
	srv.messagingPolicy.ForwardCopyTTLSeconds = apiTTLPtr(0)
	if response, body := callMessageHandler(t, srv.handleSendMessage, map[string]string{
		"recipient": elsewhereRecipient, "messageBox": "box", "body": "elsewhere copy, ttl=0",
	}); response.Code != http.StatusOK {
		t.Fatalf("elsewhere (ttl=0) send = %d, %v", response.Code, body)
	}

	time.Sleep(600 * time.Millisecond)

	if msgs, _ := srv.msgStore.List(homeRecipient, "box"); len(msgs) != 1 {
		t.Fatalf("home recipient origin-side store = %d, want 1", len(msgs))
	}
	if msgs, _ := srv.msgStore.List(elsewhereRecipient, "box"); len(msgs) != 1 {
		t.Fatalf("elsewhere recipient origin-side store = %d, want 1 (only the ttl>0 send; the ttl=0 send must not add a second row)", len(msgs))
	}
	if msgs, _ := srv.msgStore.List(unadvertisedRecipient, "box"); len(msgs) != 1 {
		t.Fatalf("unadvertised recipient origin-side store = %d, want 1", len(msgs))
	}

	if peerMsgStore.Count() != 3 {
		t.Fatalf("peer store count = %d, want 3 (elsewhere ttl>0, unadvertised, elsewhere ttl=0 — everything but the home send)", peerMsgStore.Count())
	}
	if msgs, _ := peerMsgStore.List(homeRecipient, "box"); len(msgs) != 0 {
		t.Fatalf("the Home-recipient message must never reach the peer: %+v", msgs)
	}
	if msgs, _ := peerMsgStore.List(elsewhereRecipient, "box"); len(msgs) != 2 {
		t.Fatalf("elsewhere recipient peer-side store = %d, want 2 (both the ttl>0 and ttl=0 forwards)", len(msgs))
	}
}
