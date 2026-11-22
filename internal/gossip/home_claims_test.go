package gossip

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func signedGossipHomeRecord(t *testing.T, member *ec.PrivateKey, homes []string, issuedAt int64) messaging.PrivateHomeRecord {
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

func privateHomeManager(t *testing.T) (*Manager, *messaging.PrivateHomeStore, *messaging.Store, map[string]*ec.PrivateKey) {
	t.Helper()
	keys := map[string]*ec.PrivateKey{}
	for _, name := range []string{"self", "allowed", "nonhome", "outsider", "member", "sender"} {
		key, err := ec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
	}
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	allowed := []string{hexKey("allowed"), hexKey("nonhome")}
	manager := NewManager(ManagerConfig{IdentityKey: keys["self"], AllowedPeers: allowed})
	store, err := messaging.NewStore(t.TempDir(), messaging.Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry := messaging.NewPrivateHomeStore(store, messaging.PrivateHomeOptions{
		MaxMembers: 10, MaxTTL: 3600, AllowedHomes: append(allowed, hexKey("self")),
	})
	manager.SetMsgStore(store)
	manager.SetMessagingPolicy(MessagingPolicy{PrivateHomes: registry})
	return manager, registry, store, keys
}

func TestHomeClaimAcceptedOnlyFromAllowedPeerAndRevocationUsesCutoff(t *testing.T) {
	manager, registry, _, keys := privateHomeManager(t)
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	record := signedGossipHomeRecord(t, keys["member"], []string{hexKey("allowed")}, time.Now().UnixMilli())
	raw, _ := json.Marshal(HomeClaimPayload{Records: []messaging.PrivateHomeRecord{record}})
	if err := manager.onHomeClaim(hexKey("outsider"), raw); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := registry.Current(record.Member); ok {
		t.Fatal("record from peer outside allowed_peers was accepted")
	}
	if err := manager.onHomeClaim(hexKey("allowed"), raw); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := registry.Current(record.Member); !ok {
		t.Fatal("record from allowed peer was not accepted")
	}
	revoke, _ := json.Marshal(HomeRevokePayload{Member: record.Member, BeforeIssuedAt: record.IssuedAt})
	_ = manager.onHomeRevoke(hexKey("outsider"), revoke)
	if _, ok, _ := registry.Current(record.Member); !ok {
		t.Fatal("revocation from peer outside allowed_peers was applied")
	}
	_ = manager.onHomeRevoke(hexKey("allowed"), revoke)
	if _, ok, _ := registry.Current(record.Member); ok {
		t.Fatal("revocation from allowed peer did not remove claim")
	}
	records, err := registry.Records()
	if err != nil || len(records) != 1 || records[0].Kind != messaging.PrivateHomeRelease {
		t.Fatalf("revocation tombstone = %+v, %v", records, err)
	}
}

func TestHomeAcknowledgementRequiresBothNamedHomesAndBlocksLateForward(t *testing.T) {
	manager, registry, store, keys := privateHomeManager(t)
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	homes := []string{hexKey("self"), hexKey("allowed")}
	sort.Strings(homes)
	record := signedGossipHomeRecord(t, keys["member"], homes, time.Now().UnixMilli())
	if err := registry.Apply(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	message := &messaging.Message{
		MessageID: "shared-message", Sender: hexKey("sender"), Recipient: record.Member,
		MessageBox: "inbox", Body: "ciphertext", Timestamp: time.Now().Unix(),
	}
	if inserted, err := store.Deliver(message, hexKey("allowed")); err != nil || !inserted {
		t.Fatalf("delivery = %v, %v", inserted, err)
	}
	ack, _ := json.Marshal(HomeAckPayload{Recipient: record.Member, MessageIDs: []string{message.MessageID}})
	_ = manager.onHomeAck(hexKey("nonhome"), ack)
	if messages, _ := store.List(record.Member, "inbox"); len(messages) != 1 {
		t.Fatal("allowed non-home peer acknowledgement was applied")
	}
	_ = manager.onHomeAck(hexKey("allowed"), ack)
	if messages, _ := store.List(record.Member, "inbox"); len(messages) != 0 {
		t.Fatal("named home acknowledgement did not clear message")
	}
	if inserted, err := store.Deliver(message, hexKey("allowed")); err != nil || inserted {
		t.Fatalf("late forward = %v, %v", inserted, err)
	}
}

func TestPrivateHomeForwardTargetsNamedConnectedHomesThenFallsBack(t *testing.T) {
	manager, registry, _, keys := privateHomeManager(t)
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	homes := []string{hexKey("self"), hexKey("allowed")}
	sort.Strings(homes)
	record := signedGossipHomeRecord(t, keys["member"], homes, time.Now().UnixMilli())
	if err := registry.Apply(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	manager.messagingPolicy.ForwardPeers = NewForwardPeerFilter([]string{hexKey("allowed"), hexKey("nonhome")})
	manager.peers[hexKey("allowed")] = &MeshPeer{
		Peer: &auth.Peer{}, IdentityPK: keys["allowed"].PubKey(), admitted: true,
		privateHomeVersion: privateHomeProtocolVersion, appliedHomeClaims: map[string]int64{record.Member: record.IssuedAt},
	}
	manager.peers[hexKey("nonhome")] = &MeshPeer{
		Peer: &auth.Peer{}, IdentityPK: keys["nonhome"].PubKey(), admitted: true,
		privateHomeVersion: privateHomeProtocolVersion, appliedHomeClaims: map[string]int64{record.Member: record.IssuedAt},
	}
	selected := manager.selectedForwardPeers(record.Member, "")
	if len(selected) != 1 || selected[0].identity != hexKey("allowed") {
		t.Fatalf("named targets = %+v", selected)
	}
	manager.peers[hexKey("allowed")].Peer = nil
	selected = manager.selectedForwardPeers(record.Member, "")
	if len(selected) != 1 || selected[0].identity != hexKey("nonhome") {
		t.Fatalf("fallback targets = %+v", selected)
	}
}

func TestPrivateHomeDeliveryKeepsFullTTLAtNamedHome(t *testing.T) {
	manager, registry, store, keys := privateHomeManager(t)
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	homes := []string{hexKey("self"), hexKey("allowed")}
	sort.Strings(homes)
	record := signedGossipHomeRecord(t, keys["member"], homes, time.Now().UnixMilli())
	if err := registry.Apply(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	copyTTL := int64(1)
	manager.SetMessagingPolicy(MessagingPolicy{
		PrivateHomes: registry, ForwardCopyTTLSeconds: &copyTTL,
		Home: messaging.NewPrivateHomeResolver(registry, hexKey("self"), messaging.AlwaysUnadvertised),
	})
	message := &messaging.Message{
		MessageID: "home-copy", Sender: hexKey("sender"), Recipient: record.Member,
		MessageBox: "inbox", Body: "ciphertext", Timestamp: time.Now().Unix(),
	}
	outcome := manager.deliverForward(message, hexKey("allowed"))
	if !outcome.relay {
		t.Fatal("home with another named home was not relayed")
	}
	messages, err := store.List(record.Member, "inbox")
	if err != nil || len(messages) != 1 || messages[0].ExpiryBase != 0 {
		t.Fatalf("home copy = %+v, %v", messages, err)
	}
}
