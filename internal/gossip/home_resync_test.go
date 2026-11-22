package gossip

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestInstallingPrivateHomePolicyResyncsAdmittedPeer(t *testing.T) {
	self, allowed := keysForHomePolicyTest(t)
	selfHex := hex.EncodeToString(self.PubKey().Compressed())
	allowedHex := hex.EncodeToString(allowed.PubKey().Compressed())
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	registry := messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
		MaxMembers: 10, MaxTTL: 3600, AllowedHomes: []string{selfHex, allowedHex},
	})
	manager := NewManager(ManagerConfig{IdentityKey: self, AllowedPeers: []string{allowedHex}})
	manager.SetMsgStore(store)
	transport := &silentHomeTransport{sent: make(chan struct{})}
	peer := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, self), Transport: transport})
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	manager.peers[allowedHex] = &MeshPeer{
		Peer: peer, IdentityPK: allowed.PubKey(), admitted: true,
	}
	done := make(chan struct{})
	go func() {
		manager.SetMessagingPolicy(MessagingPolicy{PrivateHomes: registry})
		close(done)
	}()
	t.Cleanup(func() {
		_ = peer.Stop()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
		}
	})
	select {
	case <-transport.sent:
	case <-time.After(time.Second):
		t.Fatal("policy installation did not resynchronize the admitted peer")
	}
}

func keysForHomePolicyTest(t *testing.T) (*ec.PrivateKey, *ec.PrivateKey) {
	t.Helper()
	first, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}
