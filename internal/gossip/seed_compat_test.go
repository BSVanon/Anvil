package gossip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestCompatibilitySeedRedialsOwnedEndpointOnceAfterDisconnect(t *testing.T) {
	upgradedKey, olderKey := orderedMeshKeys(t)
	upgradedIdentity := fmt.Sprintf("%x", upgradedKey.PubKey().Compressed())
	olderIdentity := fmt.Sprintf("%x", olderKey.PubKey().Compressed())
	upgradedReceived := make(chan string, 8)
	olderReceived := make(chan string, 8)
	upgraded := managerWithKey(t, upgradedKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		upgradedReceived <- env.Payload
	}})
	older := managerWithKey(t, olderKey, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) {
		olderReceived <- env.Payload
	}})
	older.disableDuplicateConvergence = true
	defer upgraded.Stop()
	defer older.Stop()

	serverUpgraded := httptest.NewServer(upgraded.MeshHandler())
	defer serverUpgraded.Close()
	var dialsToOlder atomic.Int32
	olderHandler := older.MeshHandler()
	serverOlder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dialsToOlder.Add(1)
		olderHandler.ServeHTTP(w, r)
	}))
	defer serverOlder.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interval := 40 * time.Millisecond
	go upgraded.ConnectSeedWithReconnect(ctx, websocketURL(serverOlder.URL), interval)
	waitForMesh(t, 5*time.Second, func() bool {
		return dialsToOlder.Load() == 1 && upgraded.hasIdentityConnection(olderIdentity) &&
			older.hasIdentityConnection(upgradedIdentity)
	})
	upgradedOutbound := peerForIdentity(upgraded, olderIdentity)
	olderInbound := peerForIdentity(older, upgradedIdentity)
	if upgradedOutbound == nil || upgradedOutbound.Direction != "outbound" ||
		olderInbound == nil || olderInbound.Direction != "inbound" {
		t.Fatalf("initial directions upgraded=%v older=%v", upgradedOutbound, olderInbound)
	}

	go older.ConnectSeedWithReconnect(ctx, websocketURL(serverUpgraded.URL), interval)
	waitForMesh(t, 5*time.Second, func() bool {
		return upgraded.PeerCount() == 2 && older.PeerCount() == 2
	})
	if peerForIdentity(upgraded, olderIdentity) != upgradedOutbound ||
		peerForIdentity(older, upgradedIdentity) != olderInbound {
		t.Fatal("reciprocal compatibility socket changed the initial primary")
	}

	if err := upgradedOutbound.closeFunc(); err != nil {
		t.Fatal(err)
	}
	waitForMesh(t, 5*time.Second, func() bool {
		return dialsToOlder.Load() == 2 && livePrimaryIsNew(older, upgradedIdentity, olderInbound) &&
			livePrimaryIsNew(upgraded, olderIdentity, upgradedOutbound)
	})
	requireConditionFor(t, 6*interval, "compatibility endpoint dialed more than once", func() bool {
		return dialsToOlder.Load() == 2
	})

	broadcastTestEnvelope(t, upgraded, upgradedKey, "upgraded-to-older")
	broadcastTestEnvelope(t, older, olderKey, "older-to-upgraded")
	waitForPayloadValue(t, olderReceived, "upgraded-to-older")
	waitForPayloadValue(t, upgradedReceived, "older-to-upgraded")
}

func orderedMeshKeys(t *testing.T) (*ec.PrivateKey, *ec.PrivateKey) {
	t.Helper()
	for {
		first, err := ec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		second, err := ec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", first.PubKey().Compressed()) < fmt.Sprintf("%x", second.PubKey().Compressed()) {
			return first, second
		}
	}
}

func livePrimaryIsNew(m *Manager, identity string, previous *MeshPeer) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peer := m.peers[identity]
	return peer != nil && peer != previous && peer.admitted && !peer.closed
}
