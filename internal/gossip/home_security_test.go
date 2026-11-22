package gossip

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

func TestPrivateHomeFallbackExcludesUnauthorizedConnections(t *testing.T) {
	manager, registry, _, keys := privateHomeManager(t)
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	record := signedGossipHomeRecord(t, keys["member"], []string{hexKey("allowed")}, time.Now().UnixMilli())
	if err := registry.Apply(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	pendingLeft, pendingRight := newMemoryHomeTransportPair()
	pendingLocal := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["self"]), Transport: pendingLeft})
	pendingRemote := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["allowed"]), Transport: pendingRight})
	disallowedLeft, disallowedRight := newMemoryHomeTransportPair()
	disallowedLocal := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["self"]), Transport: disallowedLeft})
	disallowedRemote := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["outsider"]), Transport: disallowedRight})
	received := make(chan struct{}, 2)
	for _, peer := range []*auth.Peer{pendingRemote, disallowedRemote} {
		peer.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
			received <- struct{}{}
			return nil
		})
	}
	for _, peer := range []*auth.Peer{pendingLocal, pendingRemote, disallowedLocal, disallowedRemote} {
		if err := peer.Start(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := disallowedLocal.GetAuthenticatedSession(t.Context(), keys["outsider"].PubKey(), 5000); err != nil {
		t.Fatalf("complete disallowed handshake: %v", err)
	}
	t.Cleanup(func() {
		for _, peer := range []*auth.Peer{pendingLocal, pendingRemote, disallowedLocal, disallowedRemote} {
			_ = peer.Stop()
		}
	})
	manager.peers["inbound-pending"] = &MeshPeer{Peer: pendingLocal, Endpoint: "silent"}
	manager.peers[hexKey("outsider")] = &MeshPeer{
		Peer: disallowedLocal, IdentityPK: keys["outsider"].PubKey(), admitted: false,
	}
	if selected := manager.selectedForwardPeers(record.Member, ""); len(selected) != 0 {
		t.Fatalf("unauthorized fallback targets = %+v", selected)
	}
	message := &messaging.Message{
		MessageID: "unauthorized-fallback", Sender: hexKey("sender"), Recipient: record.Member,
		MessageBox: "inbox", Body: "ciphertext", Timestamp: time.Now().Unix(),
	}
	if sent := manager.ForwardMessage(message); sent != 0 {
		t.Fatalf("private mail sent to %d unauthorized connections", sent)
	}
	select {
	case <-received:
		t.Fatal("unauthorized connection received private mail")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPrivateHomeControlFrameFromUnadmittedSocketIsRejected(t *testing.T) {
	manager, registry, _, keys := privateHomeManager(t)
	sender := hex.EncodeToString(keys["allowed"].PubKey().Compressed())
	manager.peers[sender] = &MeshPeer{Peer: &auth.Peer{}, IdentityPK: keys["allowed"].PubKey()}
	record := signedGossipHomeRecord(t, keys["member"], []string{sender}, time.Now().UnixMilli())
	payload, err := Encode(MsgHomeClaim, HomeClaimPayload{Records: []messaging.PrivateHomeRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.handleMessage(sender, keys["allowed"].PubKey(), payload); !errors.Is(err, errPeerRefused) {
		t.Fatalf("unadmitted private-home frame error = %v, want peer refusal", err)
	}
	if _, ok, err := registry.Current(record.Member); err != nil || ok {
		t.Fatalf("unadmitted frame changed registry: current=%v error=%v", ok, err)
	}
}

func TestPrivateHomeForwardWaitsForCapabilityAndClaimApplication(t *testing.T) {
	manager, registry, _, keys := privateHomeManager(t)
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	record := signedGossipHomeRecord(t, keys["member"], []string{hexKey("allowed")}, time.Now().UnixMilli())
	if err := registry.Apply(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	left, right := newMemoryHomeTransportPair()
	localPeer := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["self"]), Transport: left})
	legacyPeer := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["allowed"]), Transport: right})
	legacyForwards := make(chan struct{}, 1)
	legacyPeer.ListenForGeneralMessages(func(_ context.Context, _ *ec.PublicKey, payload []byte) error {
		message, err := Decode(payload)
		if err == nil && message.Type == MsgForward {
			legacyForwards <- struct{}{}
		}
		return nil
	})
	if err := localPeer.Start(); err != nil {
		t.Fatal(err)
	}
	if err := legacyPeer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = localPeer.Stop(); _ = legacyPeer.Stop() })
	manager.peers[hexKey("allowed")] = &MeshPeer{
		Peer: localPeer, IdentityPK: keys["allowed"].PubKey(), admitted: true,
	}
	if manager.CanApplyPrivateHomeClaim(record.Homes) {
		t.Fatal("claim accepted a connected gateway without private-home capability")
	}
	if selected := manager.selectedForwardPeers(record.Member, ""); len(selected) != 0 {
		t.Fatalf("legacy gateway selected for private mail: %+v", selected)
	}
	copyTTL := int64(0)
	manager.messagingPolicy.ForwardCopyTTLSeconds = &copyTTL
	message := &messaging.Message{
		MessageID: "legacy-only-home", Sender: hexKey("sender"), Recipient: record.Member,
		MessageBox: "inbox", Body: "ciphertext", Timestamp: time.Now().Unix(),
	}
	if sent := manager.ForwardMessage(message); sent != 0 {
		t.Fatalf("forward_copy_ttl=0 send reached %d legacy gateways", sent)
	}
	select {
	case <-legacyForwards:
		t.Fatal("legacy gateway received private mail")
	case <-time.After(50 * time.Millisecond):
	}
	status, _ := json.Marshal(HomeStatusPayload{Version: privateHomeProtocolVersion})
	if err := manager.onHomeStatus(hexKey("allowed"), status); err != nil {
		t.Fatal(err)
	}
	if selected := manager.selectedForwardPeers(record.Member, ""); len(selected) != 0 {
		t.Fatalf("gateway selected before applying claim: %+v", selected)
	}
	status, _ = json.Marshal(HomeStatusPayload{
		Version: privateHomeProtocolVersion, Applied: []HomeApplied{{Member: record.Member, IssuedAt: record.IssuedAt}},
	})
	if err := manager.onHomeStatus(hexKey("allowed"), status); err != nil {
		t.Fatal(err)
	}
	if selected := manager.selectedForwardPeers(record.Member, ""); len(selected) != 1 {
		t.Fatalf("applied capable gateway targets = %+v", selected)
	}
}

func TestPrivateHomeControlFramesUseDedicatedWorkBudget(t *testing.T) {
	manager, registry, _, keys := privateHomeManager(t)
	sender := hex.EncodeToString(keys["allowed"].PubKey().Compressed())
	record := signedGossipHomeRecord(t, keys["member"], []string{sender}, time.Now().UnixMilli())
	raw, err := json.Marshal(HomeClaimPayload{Records: []messaging.PrivateHomeRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	manager.homeRateMu.Lock()
	manager.homeRates[sender] = &homeControlRate{tokens: 0, lastSeen: time.Now()}
	manager.homeRateMu.Unlock()
	if err := manager.onHomeClaim(sender, raw); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := registry.Current(record.Member); err != nil || ok {
		t.Fatalf("rate-limited record current=%v, error=%v", ok, err)
	}
}

func TestReconnectReplaysAcknowledgementsMissedByOfflineHome(t *testing.T) {
	receiver, registry, receiverStore, keys := privateHomeManager(t)
	hexKey := func(name string) string { return hex.EncodeToString(keys[name].PubKey().Compressed()) }
	homes := []string{hexKey("allowed"), hexKey("self")}
	if homes[0] > homes[1] {
		homes[0], homes[1] = homes[1], homes[0]
	}
	claim := signedGossipHomeRecord(t, keys["member"], homes, time.Now().UnixMilli())
	if err := registry.Apply(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	message := &messaging.Message{
		MessageID: "offline-ack", Sender: hexKey("sender"), Recipient: claim.Member,
		MessageBox: "inbox", Body: "ciphertext", Timestamp: time.Now().Unix(),
	}
	if inserted, err := receiverStore.Deliver(message, hexKey("allowed")); err != nil || !inserted {
		t.Fatalf("receiver delivery = %v, %v", inserted, err)
	}
	sourceStore, err := messaging.NewStore(t.TempDir(), messaging.Options{TTLSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	defer sourceStore.Close()
	sourceRegistry := messaging.NewPrivateHomeStore(sourceStore, messaging.PrivateHomeOptions{
		MaxMembers: 10, MaxTTL: 3600, AllowedHomes: homes,
	})
	if err := sourceRegistry.Apply(context.Background(), claim); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceStore.Acknowledge(claim.Member, []string{message.MessageID}); err != nil {
		t.Fatal(err)
	}
	source := NewManager(ManagerConfig{
		Wallet: wallet.NewTestWallet(t, keys["allowed"]), IdentityKey: keys["allowed"], AllowedPeers: []string{hexKey("self")},
	})
	source.SetMsgStore(sourceStore)
	source.SetMessagingPolicy(MessagingPolicy{PrivateHomes: sourceRegistry})
	failedTransport := &failingHomeTransport{}
	failedPeer := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["allowed"]), Transport: failedTransport})
	if err := failedPeer.Start(); err != nil {
		t.Fatal(err)
	}
	source.peers[hexKey("self")] = &MeshPeer{
		Peer: failedPeer, IdentityPK: keys["self"].PubKey(), admitted: true,
	}
	source.BroadcastHomeAck(claim.Member, []string{message.MessageID})
	_ = failedPeer.Stop()
	delete(source.peers, hexKey("self"))
	left, right := newMemoryHomeTransportPair()
	sourcePeer := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["allowed"]), Transport: left})
	receiverPeer := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["self"]), Transport: right})
	replayed := make(chan []byte, 1)
	receiverPeer.ListenForGeneralMessages(func(_ context.Context, _ *ec.PublicKey, payload []byte) error {
		replayed <- payload
		return nil
	})
	if err := sourcePeer.Start(); err != nil {
		t.Fatal(err)
	}
	if err := receiverPeer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sourcePeer.Stop(); _ = receiverPeer.Stop() })
	source.announcePrivateHomeAcks(peerSendTarget{
		peer: sourcePeer, identityPK: keys["self"].PubKey(), identity: hexKey("self"),
	}, nil)
	var replayedMessage Message
	select {
	case payload := <-replayed:
		decoded, decodeErr := Decode(payload)
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		replayedMessage = *decoded
	case <-time.After(time.Second):
		t.Fatal("reconnect did not replay acknowledgement tombstone")
	}
	if replayedMessage.Type != MsgHomeAck {
		t.Fatalf("reconnect message type = %s", replayedMessage.Type)
	}
	if err := receiver.onHomeAck(hexKey("allowed"), replayedMessage.Data); err != nil {
		t.Fatal(err)
	}
	if messages, err := receiverStore.List(claim.Member, "inbox"); err != nil || len(messages) != 0 {
		t.Fatalf("messages after reconnect ack = %+v, %v", messages, err)
	}
	if inserted, err := receiverStore.Deliver(message, hexKey("allowed")); err != nil || inserted {
		t.Fatalf("late forward after reconnect ack = %v, %v", inserted, err)
	}
}

type failingHomeTransport struct {
	onData func(context.Context, *auth.AuthMessage) error
}

func (*failingHomeTransport) Send(context.Context, *auth.AuthMessage) error {
	return errors.New("send failed")
}

func (t *failingHomeTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	t.onData = callback
	return nil
}

func (t *failingHomeTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	return t.onData, nil
}

type memoryHomeTransport struct {
	paired *memoryHomeTransport
	onData func(context.Context, *auth.AuthMessage) error
}

func newMemoryHomeTransportPair() (*memoryHomeTransport, *memoryHomeTransport) {
	left, right := &memoryHomeTransport{}, &memoryHomeTransport{}
	left.paired, right.paired = right, left
	return left, right
}

func (t *memoryHomeTransport) Send(ctx context.Context, message *auth.AuthMessage) error {
	return t.paired.onData(ctx, message)
}

func (t *memoryHomeTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	t.onData = callback
	return nil
}

func (t *memoryHomeTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	return t.onData, nil
}

type silentHomeTransport struct {
	once   sync.Once
	sent   chan struct{}
	onData func(context.Context, *auth.AuthMessage) error
}

func (t *silentHomeTransport) Send(context.Context, *auth.AuthMessage) error {
	t.once.Do(func() { close(t.sent) })
	return nil
}

func (t *silentHomeTransport) OnData(callback func(context.Context, *auth.AuthMessage) error) error {
	t.onData = callback
	return nil
}

func (t *silentHomeTransport) GetRegisteredOnData() (func(context.Context, *auth.AuthMessage) error, error) {
	return t.onData, nil
}

func TestPrivateHomeBroadcastReleasesManagerLockBeforeNetworkWait(t *testing.T) {
	manager, _, _, keys := privateHomeManager(t)
	allowed := hex.EncodeToString(keys["allowed"].PubKey().Compressed())
	transport := &silentHomeTransport{sent: make(chan struct{})}
	peer := auth.NewPeer(&auth.PeerOptions{Wallet: wallet.NewTestWallet(t, keys["self"]), Transport: transport})
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.peers[allowed] = &MeshPeer{
		Peer: peer, IdentityPK: keys["allowed"].PubKey(), admitted: true,
	}
	manager.mu.Unlock()
	record := signedGossipHomeRecord(t, keys["member"], []string{allowed}, time.Now().UnixMilli())
	done := make(chan struct{})
	go func() {
		manager.BroadcastHomeRecord(record)
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
		t.Fatal("private-home broadcast did not start network send")
	}
	lockAcquired := make(chan struct{})
	go func() {
		manager.mu.Lock()
		manager.mu.Unlock()
		close(lockAcquired)
	}()
	select {
	case <-lockAcquired:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("manager write lock waited behind private-home network send")
	}
	select {
	case <-done:
		t.Fatal("silent send returned before the lock-progress assertion")
	default:
	}
}
