package gossip

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"golang.org/x/net/websocket"
)

const admissionTestLocalIdentity = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestSilentInboundConnectionReceivesNoApplicationFanout(t *testing.T) {
	mgr, attacker, cleanup, _, _, _ := newUnadmittedFanoutPeer(t, nil)
	defer cleanup()

	mgr.ReannounceToAll()
	if sent := mgr.ForwardMessage(&messaging.Message{MessageID: "silent-inbound"}); sent != 0 {
		t.Fatalf("message forward reported %d sends, want 0", sent)
	}
	time.Sleep(200 * time.Millisecond)
	if got := attacker.received.Load(); got != 0 {
		t.Fatalf("silent inbound connection received %d application messages, want 0", got)
	}
}

func TestIdentifiedDisallowedConnectionReceivesNoApplicationFanout(t *testing.T) {
	mgr, attacker, cleanup, tempKey, attackerHex, attackerPK := newUnadmittedFanoutPeer(t, []string{strangerHex})
	defer cleanup()

	mgr.mu.Lock()
	mp := mgr.peers[tempKey]
	mp.IdentityPK = attackerPK
	mgr.peers[attackerHex] = mp
	delete(mgr.peers, tempKey)
	mgr.mu.Unlock()

	mgr.ReannounceToAll()
	if sent := mgr.ForwardMessage(&messaging.Message{MessageID: "disallowed-inbound"}); sent != 0 {
		t.Fatalf("message forward reported %d sends, want 0", sent)
	}
	time.Sleep(200 * time.Millisecond)
	if got := attacker.received.Load(); got != 0 {
		t.Fatalf("identified disallowed connection received %d application messages, want 0", got)
	}
}

func newUnadmittedFanoutPeer(t *testing.T, allowed []string) (*Manager, *rawCountingPeer, func(), string, string, *ec.PublicKey) {
	t.Helper()
	listenerWallet, _ := newIdentity(t)
	attackerWallet, attackerHex, attackerKey := newIdentityWithKey(t)
	dir := &mockOverlayDir{entries: []struct{ identity, domain, nodeName, version, topic string }{
		{admissionTestLocalIdentity, "https://node.example", "node", "1", "anvil:mainnet"},
	}}
	mgr := NewManager(ManagerConfig{
		Wallet: listenerWallet, OverlayDir: dir, LocalPubkeys: []string{admissionTestLocalIdentity},
		AllowedPeers: allowed,
	})

	registered := make(chan string, 1)
	handler := websocket.Handler(func(conn *websocket.Conn) {
		transport := NewServerWSTransport(conn)
		key, err := mgr.AcceptPeer(transport)
		if err != nil {
			t.Errorf("AcceptPeer: %v", err)
			registered <- ""
			return
		}
		registered <- key
		<-transport.Done()
	})
	server := httptest.NewServer(handler)
	transport, err := NewWSTransportAdapter(websocketURL(server.URL))
	if err != nil {
		server.Close()
		t.Fatalf("dial: %v", err)
	}
	attacker := newRawCountingPeerOn(t, transport, auth.PeerOptions{Wallet: attackerWallet, Transport: transport})
	tempKey := <-registered
	if tempKey == "" {
		t.Fatal("inbound connection was not registered")
	}
	cleanup := func() {
		_ = transport.Close()
		mgr.Stop()
		server.Close()
	}
	return mgr, attacker, cleanup, tempKey, attackerHex, attackerKey.PubKey()
}
