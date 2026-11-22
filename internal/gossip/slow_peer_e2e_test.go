package gossip

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

type admittedStalledPeer struct {
	peer      *auth.Peer
	transport *ServerWSTransport
	blocked   chan struct{}
	release   chan struct{}
	blockOnce sync.Once
	closeOnce sync.Once
	identity  string
}

func connectAdmittedStalledPeer(t *testing.T, manager *Manager, endpoint string) *admittedStalledPeer {
	t.Helper()
	wallet, identity, _ := newIdentityWithKey(t)
	transport, err := NewWSTransportAdapter(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	stalled := &admittedStalledPeer{
		transport: transport,
		blocked:   make(chan struct{}),
		release:   make(chan struct{}),
		identity:  identity,
	}
	stalled.peer = auth.NewPeer(&auth.PeerOptions{Wallet: wallet, Transport: transport})
	stalled.peer.ListenForGeneralMessages(func(context.Context, *ec.PublicKey, []byte) error {
		stalled.blockOnce.Do(func() { close(stalled.blocked) })
		<-stalled.release
		return nil
	})
	if err := stalled.peer.Start(); err != nil {
		t.Fatal(err)
	}
	go transport.StartReceive()
	t.Cleanup(func() {
		stalled.closeOnce.Do(func() { close(stalled.release) })
		_ = stalled.peer.Stop()
		_ = transport.Close()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	session, err := stalled.peer.GetAuthenticatedSession(ctx, nil, 10000)
	if err != nil {
		t.Fatalf("stalled peer handshake: %v", err)
	}
	topics, err := Encode(MsgTopics, TopicsPayload{Prefixes: []string{""}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stalled.peer.ToPeer(ctx, topics, session.PeerIdentityKey, 5000); err != nil {
		t.Fatalf("stalled peer topic announce: %v", err)
	}
	waitForMesh(t, 3*time.Second, func() bool {
		prefixes := manager.Interests()[identity]
		return len(prefixes) == 1 && prefixes[0] == ""
	})
	select {
	case <-stalled.blocked:
	case <-time.After(time.Second):
		t.Fatal("stalled peer did not stop its receive loop")
	}
	return stalled
}

func meshBurstEnvelope(t *testing.T, key *ec.PrivateKey, sequence int) *envelope.Envelope {
	t.Helper()
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "stall:test",
		Payload:   strings.Repeat("x", 20<<10) + fmt.Sprintf("-%04d", sequence),
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)
	return env
}

func callBroadcastPromptly(t *testing.T, manager *Manager, env *envelope.Envelope) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		manager.BroadcastEnvelope(env)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("BroadcastEnvelope blocked on a peer socket")
	}
}

func managerTransportFor(t *testing.T, manager *Manager, identity string) *ServerWSTransport {
	t.Helper()
	manager.mu.RLock()
	peer := manager.peers[identity]
	manager.mu.RUnlock()
	if peer == nil || peer.transport == nil {
		t.Fatalf("no transport for peer %s", truncate(identity))
	}
	return peer.transport
}

func configureShortWriteTimeout(transport *ServerWSTransport) {
	transport.writeMu.Lock()
	transport.writeTimeout = 100 * time.Millisecond
	transport.minWriteRate = 1 << 30
	transport.writeMu.Unlock()
}

func waitUntilTransportReady(t *testing.T, transport *ServerWSTransport) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for transport.Backlogged() {
		if time.Now().After(deadline) {
			t.Fatal("healthy peer transport did not drain below the soft bound")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSlowPeerCannotBlockBroadcastToHealthyPeer(t *testing.T) {
	var healthyReceived atomic.Int64
	mKey, _ := ec.NewPrivateKey()
	m := managerWithKey(t, mKey, ManagerConfig{RatePerSec: 10000, RateBurst: 1000})
	defer m.Stop()
	server := httptest.NewServer(m.MeshHandler())
	defer server.Close()

	hKey, _ := ec.NewPrivateKey()
	h := managerWithKey(t, hKey, ManagerConfig{
		RatePerSec: 10000,
		RateBurst:  1000,
		OnEnvelope: func(*envelope.Envelope) { healthyReceived.Add(1) },
	})
	defer h.Stop()
	if err := h.ConnectPeer(t.Context(), websocketURL(server.URL)); err != nil {
		t.Fatal(err)
	}
	slow := connectAdmittedStalledPeer(t, m, websocketURL(server.URL))
	slowOnManager := managerTransportFor(t, m, slow.identity)
	configureShortWriteTimeout(slowOnManager)
	healthyIdentity := fmt.Sprintf("%x", hKey.PubKey().Compressed())
	waitForMesh(t, 3*time.Second, func() bool {
		return m.PeerCount() == 2 && len(m.Interests()[healthyIdentity]) == 1
	})
	healthyOnManager := managerTransportFor(t, m, healthyIdentity)

	publisher, _ := ec.NewPrivateKey()
	const total = 320
	for i := 0; i < total; i++ {
		waitUntilTransportReady(t, healthyOnManager)
		callBroadcastPromptly(t, m, meshBurstEnvelope(t, publisher, i))
		time.Sleep(10 * time.Millisecond)
	}
	waitForMesh(t, 10*time.Second, func() bool { return healthyReceived.Load() == total })
	waitForMesh(t, 2*time.Second, func() bool { return m.PeerCount() == 1 })
	if got := healthyOnManager.CloseReason(); got != "" {
		t.Fatalf("healthy peer transport closed: %s", got)
	}
	if got := slowOnManager.CloseReason(); got != transportCloseTimeout && got != transportCloseQueueFull {
		t.Fatalf("slow peer close reason = %q", got)
	}
}

func TestSlowPeerCannotBlockAnotherPeersReadLoop(t *testing.T) {
	var managerReceived atomic.Int64
	mKey, _ := ec.NewPrivateKey()
	m := managerWithKey(t, mKey, ManagerConfig{
		RatePerSec: 10000,
		RateBurst:  1000,
		OnEnvelope: func(*envelope.Envelope) { managerReceived.Add(1) },
	})
	defer m.Stop()
	server := httptest.NewServer(m.MeshHandler())
	defer server.Close()

	hKey, _ := ec.NewPrivateKey()
	h := managerWithKey(t, hKey, ManagerConfig{RatePerSec: 10000, RateBurst: 1000})
	defer h.Stop()
	if err := h.ConnectPeer(t.Context(), websocketURL(server.URL)); err != nil {
		t.Fatal(err)
	}
	slow := connectAdmittedStalledPeer(t, m, websocketURL(server.URL))
	configureShortWriteTimeout(managerTransportFor(t, m, slow.identity))
	healthyIdentity := fmt.Sprintf("%x", hKey.PubKey().Compressed())
	managerIdentity := fmt.Sprintf("%x", mKey.PubKey().Compressed())
	waitForMesh(t, 3*time.Second, func() bool {
		return m.PeerCount() == 2 && len(h.Interests()[managerIdentity]) == 1
	})
	healthyOnSender := managerTransportFor(t, h, managerIdentity)
	healthyOnManager := managerTransportFor(t, m, healthyIdentity)

	publisher, _ := ec.NewPrivateKey()
	const total = 320
	for i := 0; i < total; i++ {
		waitUntilTransportReady(t, healthyOnSender)
		callBroadcastPromptly(t, h, meshBurstEnvelope(t, publisher, i))
		time.Sleep(10 * time.Millisecond)
	}
	waitForMesh(t, 10*time.Second, func() bool { return managerReceived.Load() == total })
	waitForMesh(t, 2*time.Second, func() bool { return m.PeerCount() == 1 })
	if got := healthyOnManager.CloseReason(); got != "" {
		t.Fatalf("healthy peer transport closed: %s", got)
	}
}
