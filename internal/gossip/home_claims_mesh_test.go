package gossip

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

type privateHomeMeshNode struct {
	manager  *Manager
	registry *messaging.PrivateHomeStore
	store    *messaging.Store
	key      *ec.PrivateKey
}

func newPrivateHomeMeshNode(t *testing.T, key *ec.PrivateKey, allowed, homes []string) privateHomeMeshNode {
	t.Helper()
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry := messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
		MaxMembers: 10, MaxTTL: 3600, AllowedHomes: homes,
	})
	manager := NewManager(ManagerConfig{
		Wallet: wallet.NewTestWallet(t, key), IdentityKey: key, AllowedPeers: allowed,
	})
	manager.SetMsgStore(store)
	copyTTL := int64(1)
	manager.SetMessagingPolicy(MessagingPolicy{
		PrivateHomes:          registry,
		Home:                  messaging.NewPrivateHomeResolver(registry, hex.EncodeToString(key.PubKey().Compressed()), messaging.AlwaysUnadvertised),
		ForwardCopyTTLSeconds: &copyTTL,
	})
	t.Cleanup(manager.Stop)
	return privateHomeMeshNode{manager: manager, registry: registry, store: store, key: key}
}

func waitForPrivateHomeClaim(t *testing.T, registry *messaging.PrivateHomeStore, member string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok, _ := registry.Current(member); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("private home claim did not arrive")
}

func waitForPrivateHomeMessage(t *testing.T, store *messaging.Store, recipient string) *messaging.StoredMessage {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		messages, _ := store.List(recipient, "inbox")
		if len(messages) == 1 {
			return messages[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("private home message did not arrive")
	return nil
}

func waitForPrivateHomeAck(t *testing.T, store *messaging.Store, recipient string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		messages, _ := store.List(recipient, "inbox")
		if len(messages) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("private home acknowledgement did not arrive")
}

func waitForPrivateHomeForwardTarget(t *testing.T, manager *Manager, recipient string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(manager.selectedForwardPeers(recipient, "")) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("private home did not acknowledge the claim version")
}

func TestPrivateHomeMeshPropagationAndConnectSync(t *testing.T) {
	keys := make([]*ec.PrivateKey, 3)
	hexes := make([]string, 3)
	for i := range keys {
		key, err := ec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
		hexes[i] = hex.EncodeToString(key.PubKey().Compressed())
	}
	allHomes := append([]string(nil), hexes...)
	sort.Strings(allHomes)
	g1 := newPrivateHomeMeshNode(t, keys[0], []string{hexes[1], hexes[2]}, allHomes)
	g2 := newPrivateHomeMeshNode(t, keys[1], []string{hexes[0], hexes[2]}, allHomes)
	g3 := newPrivateHomeMeshNode(t, keys[2], []string{hexes[0], hexes[1]}, allHomes)
	server := httptest.NewServer(g1.manager.MeshHandler())
	t.Cleanup(server.Close)
	endpoint := "ws" + server.URL[len("http"):]
	if err := g2.manager.ConnectPeer(t.Context(), endpoint); err != nil {
		t.Fatal(err)
	}

	member, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{hexes[0], hexes[1]}
	sort.Strings(selected)
	record := signedGossipHomeRecord(t, member, selected, time.Now().UnixMilli())
	if err := g1.registry.Apply(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	g1.manager.BroadcastHomeRecord(record)
	waitForPrivateHomeClaim(t, g2.registry, record.Member)
	waitForPrivateHomeForwardTarget(t, g1.manager, record.Member)

	if err := g3.manager.ConnectPeer(t.Context(), endpoint); err != nil {
		t.Fatal(err)
	}
	waitForPrivateHomeClaim(t, g3.registry, record.Member)
	waitForPrivateHomeForwardTarget(t, g3.manager, record.Member)

	sender, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	message := &messaging.Message{
		MessageID: "private-home-delivery", Sender: hex.EncodeToString(sender.PubKey().Compressed()),
		Recipient: record.Member, MessageBox: "inbox", Body: "ciphertext", Timestamp: time.Now().Unix(),
	}
	if sent := g3.manager.ForwardMessage(message); sent != 1 {
		t.Fatalf("forward sent to %d peers, want one connected named home", sent)
	}
	for name, node := range map[string]privateHomeMeshNode{"G1": g1, "G2": g2} {
		stored := waitForPrivateHomeMessage(t, node.store, record.Member)
		if stored.ExpiryBase != 0 {
			t.Fatalf("%s home copy used shortened expiry base %d", name, stored.ExpiryBase)
		}
	}
	if _, err := g1.store.Acknowledge(record.Member, []string{message.MessageID}); err != nil {
		t.Fatal(err)
	}
	g1.manager.BroadcastHomeAck(record.Member, []string{message.MessageID})
	waitForPrivateHomeAck(t, g2.store, record.Member)
	before, changed, err := g1.registry.RevokeMember(record.Member)
	if err != nil || !changed {
		t.Fatalf("local revocation = %v, %v", changed, err)
	}
	g1.manager.BroadcastHomeRevoke(record.Member, before)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, g2Current, _ := g2.registry.Current(record.Member)
		_, g3Current, _ := g3.registry.Current(record.Member)
		if !g2Current && !g3Current {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("private home revocation did not reach every allowed gateway")
}
