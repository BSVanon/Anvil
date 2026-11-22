package gossip

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestSilentSameDirectionConnectionIsReplaced(t *testing.T) {
	setStaleDuplicateWindow(t, 100*time.Millisecond)
	remoteKey, _ := ec.NewPrivateKey()
	hubKey, _ := ec.NewPrivateKey()
	hubReceived := make(chan string, 8)
	replacementReceived := make(chan string, 8)
	old := managerWithKey(t, remoteKey, ManagerConfig{})
	replacement := managerWithKey(t, remoteKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		replacementReceived <- env.Payload
	}})
	hub := managerWithKey(t, hubKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		hubReceived <- env.Payload
	}})
	hub.connLog = &ConnectionLog{maxRecent: 20}
	defer old.Stop()
	defer replacement.Stop()
	defer hub.Stop()
	server := httptest.NewServer(hub.MeshHandler())
	defer server.Close()

	endpoint := websocketURL(server.URL)
	if err := old.ConnectPeer(t.Context(), endpoint); err != nil {
		t.Fatal(err)
	}
	remoteIdentity := fmt.Sprintf("%x", remoteKey.PubKey().Compressed())
	hubIdentity := fmt.Sprintf("%x", hubKey.PubKey().Compressed())
	waitForMesh(t, time.Second, func() bool {
		return peerForIdentity(hub, remoteIdentity) != nil && identitySupportsExactRemoval(hub, remoteIdentity)
	})
	oldPrimary := peerForIdentity(hub, remoteIdentity)
	waitForMesh(t, time.Second, func() bool {
		return frameIsStale(oldPrimary)
	})

	if err := replacement.ConnectPeer(t.Context(), endpoint); err != nil {
		t.Fatalf("replacement connect: %v", err)
	}
	waitForMesh(t, time.Second, func() bool {
		primary := peerForIdentity(hub, remoteIdentity)
		return primary != nil && primary != oldPrimary && peerClosedWith(hub, oldPrimary, "duplicate_connection")
	})
	if !hasDisconnectReason(hub, remoteIdentity, "duplicate_connection") {
		t.Fatal("replaced connection did not record duplicate_connection")
	}
	waitForMesh(t, time.Second, func() bool { return len(replacement.Interests()[hubIdentity]) > 0 })

	broadcastTestEnvelope(t, replacement, remoteKey, "replacement-to-hub")
	broadcastTestEnvelope(t, hub, hubKey, "hub-to-replacement")
	waitForPayloadValue(t, hubReceived, "replacement-to-hub")
	waitForPayloadValue(t, replacementReceived, "hub-to-replacement")
}

func TestLiveSameDirectionConnectionRejectsReplacement(t *testing.T) {
	setStaleDuplicateWindow(t, 150*time.Millisecond)
	remoteKey, _ := ec.NewPrivateKey()
	hubKey, _ := ec.NewPrivateKey()
	hubReceived := make(chan string, 32)
	oldReceived := make(chan string, 8)
	old := managerWithKey(t, remoteKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		oldReceived <- env.Payload
	}})
	replacement := managerWithKey(t, remoteKey, ManagerConfig{})
	hub := managerWithKey(t, hubKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		hubReceived <- env.Payload
	}})
	defer old.Stop()
	defer replacement.Stop()
	defer hub.Stop()
	server := httptest.NewServer(hub.MeshHandler())
	defer server.Close()

	endpoint := websocketURL(server.URL)
	if err := old.ConnectPeer(t.Context(), endpoint); err != nil {
		t.Fatal(err)
	}
	remoteIdentity := fmt.Sprintf("%x", remoteKey.PubKey().Compressed())
	hubIdentity := fmt.Sprintf("%x", hubKey.PubKey().Compressed())
	waitForMesh(t, time.Second, func() bool {
		return peerForIdentity(hub, remoteIdentity) != nil && identitySupportsExactRemoval(hub, remoteIdentity)
	})
	oldPrimary := peerForIdentity(hub, remoteIdentity)

	stopFrames := make(chan struct{})
	var sequence atomic.Int32
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopFrames:
				return
			case <-ticker.C:
				broadcastTestEnvelope(t, old, remoteKey, fmt.Sprintf("keepalive-%d", sequence.Add(1)))
			}
		}
	}()
	waitForPayloadValue(t, hubReceived, "keepalive-1")
	err := replacement.ConnectPeer(t.Context(), endpoint)
	close(stopFrames)
	if err != nil && !errors.Is(err, errDuplicateConnection) {
		t.Fatalf("live duplicate error = %v", err)
	}
	waitForMesh(t, time.Second, func() bool {
		return peerForIdentity(hub, remoteIdentity) == oldPrimary && len(connectionPointers(hub)) == 1
	})
	waitForMesh(t, time.Second, func() bool { return len(old.Interests()[hubIdentity]) > 0 })

	broadcastTestEnvelope(t, old, remoteKey, "old-to-hub")
	broadcastTestEnvelope(t, hub, hubKey, "hub-to-old")
	waitForPayloadValue(t, hubReceived, "old-to-hub")
	waitForPayloadValue(t, oldReceived, "hub-to-old")
}

func TestPeerWithoutExactRemovalRetainsSameDirectionSockets(t *testing.T) {
	setStaleDuplicateWindow(t, 80*time.Millisecond)
	remoteKey, _ := ec.NewPrivateKey()
	hubKey, _ := ec.NewPrivateKey()
	hubReceived := make(chan string, 8)
	oldReceived := make(chan string, 8)
	old := managerWithKey(t, remoteKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		oldReceived <- env.Payload
	}})
	replacement := managerWithKey(t, remoteKey, ManagerConfig{})
	hub := managerWithKey(t, hubKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		hubReceived <- env.Payload
	}})
	hub.disableDuplicateConvergence = true
	defer old.Stop()
	defer replacement.Stop()
	defer hub.Stop()
	server := httptest.NewServer(hub.MeshHandler())
	defer server.Close()

	endpoint := websocketURL(server.URL)
	if err := old.ConnectPeer(t.Context(), endpoint); err != nil {
		t.Fatal(err)
	}
	remoteIdentity := fmt.Sprintf("%x", remoteKey.PubKey().Compressed())
	hubIdentity := fmt.Sprintf("%x", hubKey.PubKey().Compressed())
	waitForMesh(t, time.Second, func() bool { return peerForIdentity(hub, remoteIdentity) != nil })
	oldPrimary := peerForIdentity(hub, remoteIdentity)
	waitForMesh(t, time.Second, func() bool { return frameIsStale(oldPrimary) })
	if err := replacement.ConnectPeer(t.Context(), endpoint); err != nil {
		t.Fatalf("compatibility connect: %v", err)
	}
	if primary := peerForIdentity(hub, remoteIdentity); primary != oldPrimary {
		t.Fatal("compatibility peer changed the preferred socket")
	}
	if got := len(connectionPointers(hub)); got != 2 {
		t.Fatalf("compatibility peer retained %d sockets, want 2", got)
	}
	if peerClosedWith(hub, oldPrimary, "") {
		t.Fatal("compatibility peer closed the existing socket")
	}
	waitForMesh(t, time.Second, func() bool { return len(replacement.Interests()[hubIdentity]) > 0 })

	broadcastTestEnvelope(t, replacement, remoteKey, "second-to-hub")
	broadcastTestEnvelope(t, hub, hubKey, "hub-to-existing")
	waitForPayloadValue(t, hubReceived, "second-to-hub")
	waitForPayloadValue(t, oldReceived, "hub-to-existing")
}

func setStaleDuplicateWindow(t *testing.T, window time.Duration) {
	t.Helper()
	previous := staleDuplicateAfter
	staleDuplicateAfter = window
	t.Cleanup(func() { staleDuplicateAfter = previous })
}

func frameIsStale(peer *MeshPeer) bool {
	return peer != nil && time.Since(time.Unix(0, peer.lastFrameAt.Load())) > staleDuplicateAfter
}

func identitySupportsExactRemoval(m *Manager, identity string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.duplicateSafePeers[identity]
	return ok
}

func peerClosedWith(m *Manager, peer *MeshPeer, reason string) bool {
	if peer == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return peer.closed && (reason == "" || peer.closeReason == reason)
}

func hasDisconnectReason(m *Manager, identity, reason string) bool {
	for _, event := range m.RecentConnections(20) {
		if event.Event == "disconnected" && event.Identity == identity && event.Reason == reason {
			return true
		}
	}
	return false
}

func waitForPayloadValue(t *testing.T, received <-chan string, want string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case got := <-received:
			if got == want {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}
