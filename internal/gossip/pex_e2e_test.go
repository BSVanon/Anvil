package gossip

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestReciprocalSeedsConvergeWithoutChurnAndReconnect(t *testing.T) {
	keyA, _ := ec.NewPrivateKey()
	keyB, _ := ec.NewPrivateKey()
	receivedA := make(chan string, 4)
	receivedB := make(chan string, 4)
	mgrA := managerWithKey(t, keyA, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) { receivedA <- env.Payload }})
	mgrB := managerWithKey(t, keyB, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) { receivedB <- env.Payload }})
	defer mgrA.Stop()
	defer mgrB.Stop()
	serverA := httptest.NewServer(mgrA.MeshHandler())
	serverB := httptest.NewServer(mgrB.MeshHandler())
	defer serverA.Close()
	defer serverB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interval := 40 * time.Millisecond
	go mgrA.ConnectSeedWithReconnect(ctx, websocketURL(serverB.URL), interval)
	go mgrB.ConnectSeedWithReconnect(ctx, websocketURL(serverA.URL), interval)
	identityA := fmt.Sprintf("%x", keyA.PubKey().Compressed())
	identityB := fmt.Sprintf("%x", keyB.PubKey().Compressed())
	wantDirectionA, wantDirectionB := "inbound", "outbound"
	if identityA < identityB {
		wantDirectionA, wantDirectionB = "outbound", "inbound"
	}
	waitForMesh(t, 8*time.Second, func() bool {
		return mgrA.PeerCount() == 1 && mgrB.PeerCount() == 1 &&
			directionForIdentity(mgrA, identityB) == wantDirectionA &&
			directionForIdentity(mgrB, identityA) == wantDirectionB
	})
	if directionForIdentity(mgrA, identityB) != wantDirectionA || directionForIdentity(mgrB, identityA) != wantDirectionB {
		t.Fatalf("directions A=%s B=%s, want A=%s B=%s",
			directionForIdentity(mgrA, identityB), directionForIdentity(mgrB, identityA), wantDirectionA, wantDirectionB)
	}
	peerA := peerForIdentity(mgrA, identityB)
	peerB := peerForIdentity(mgrB, identityA)
	requireConditionFor(t, 5*interval, "reciprocal seed connections changed", func() bool {
		return peerForIdentity(mgrA, identityB) == peerA && peerForIdentity(mgrB, identityA) == peerB
	})
	if peerForIdentity(mgrA, identityB) != peerA || peerForIdentity(mgrB, identityA) != peerB {
		t.Fatal("reciprocal seeds churned after duplicate convergence")
	}

	broadcastTestEnvelope(t, mgrA, keyA, "from-a")
	broadcastTestEnvelope(t, mgrB, keyB, "from-b")
	waitForPayload(t, receivedA, "from-b")
	waitForPayload(t, receivedB, "from-a")

	kept := peerA
	if wantDirectionB == "outbound" {
		kept = peerB
	}
	_ = kept.closeFunc()
	waitForMesh(t, 8*time.Second, func() bool {
		return mgrA.PeerCount() == 1 && mgrB.PeerCount() == 1 &&
			peerForIdentity(mgrA, identityB) != peerA && peerForIdentity(mgrB, identityA) != peerB &&
			len(mgrA.Interests()[identityB]) > 0 && len(mgrB.Interests()[identityA]) > 0
	})
	broadcastTestEnvelope(t, mgrA, keyA, "after-reconnect")
	waitForPayload(t, receivedB, "after-reconnect")
}

func TestReciprocalSeedsRetainCompatibilitySocketsWithoutChurn(t *testing.T) {
	keyA, _ := ec.NewPrivateKey()
	keyB, _ := ec.NewPrivateKey()
	receivedA := make(chan string, 2)
	receivedB := make(chan string, 2)
	mgrA := managerWithKey(t, keyA, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) { receivedA <- env.Payload }})
	mgrB := managerWithKey(t, keyB, ManagerConfig{OnEnvelope: func(env *envelope.Envelope) { receivedB <- env.Payload }})
	mgrB.disableDuplicateConvergence = true
	defer mgrA.Stop()
	defer mgrB.Stop()
	serverA := httptest.NewServer(mgrA.MeshHandler())
	serverB := httptest.NewServer(mgrB.MeshHandler())
	defer serverA.Close()
	defer serverB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interval := 40 * time.Millisecond
	go mgrA.ConnectSeedWithReconnect(ctx, websocketURL(serverB.URL), interval)
	go mgrB.ConnectSeedWithReconnect(ctx, websocketURL(serverA.URL), interval)
	waitForMesh(t, 8*time.Second, func() bool {
		return mgrA.PeerCount() == 2 && mgrB.PeerCount() == 2 &&
			len(mgrA.Interests()) == 1 && len(mgrB.Interests()) == 1
	})

	peersA := connectionPointers(mgrA)
	peersB := connectionPointers(mgrB)
	requireConditionFor(t, 5*interval, "compatibility sockets changed", func() bool {
		return sameConnectionPointers(peersA, connectionPointers(mgrA)) &&
			sameConnectionPointers(peersB, connectionPointers(mgrB))
	})
	if !sameConnectionPointers(peersA, connectionPointers(mgrA)) ||
		!sameConnectionPointers(peersB, connectionPointers(mgrB)) {
		t.Fatal("compatibility sockets churned across reconnect intervals")
	}

	broadcastTestEnvelope(t, mgrA, keyA, "compat-from-a")
	broadcastTestEnvelope(t, mgrB, keyB, "compat-from-b")
	waitForPayload(t, receivedA, "compat-from-b")
	waitForPayload(t, receivedB, "compat-from-a")
}

func TestSelfSeedDialsOnceAndSendsNoAnnounce(t *testing.T) {
	key, _ := ec.NewPrivateKey()
	mgr := managerWithKey(t, key, ManagerConfig{})
	defer mgr.Stop()
	var requests atomic.Int32
	handler := mgr.MeshHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interval := 30 * time.Millisecond
	go mgr.ConnectSeedWithReconnect(ctx, websocketURL(server.URL), interval)
	waitForMesh(t, 5*time.Second, func() bool { return requests.Load() == 1 })
	requireConditionFor(t, 6*interval, "self seed redialed", func() bool { return requests.Load() == 1 })
	if requests.Load() != 1 {
		t.Fatalf("self seed dialed %d times", requests.Load())
	}
	if mgr.PeerCount() != 0 || len(mgr.Interests()) != 0 {
		t.Fatalf("self seed retained peer or announce: peers=%d interests=%v", mgr.PeerCount(), mgr.Interests())
	}
}

func TestPeerExchangeLearnsRelayedHeartbeatAndChecksIdentity(t *testing.T) {
	allowLoopbackExchangeDial.Store(true)
	t.Cleanup(func() { allowLoopbackExchangeDial.Store(false) })
	oldInterval := peerExchangeDialInterval
	peerExchangeDialInterval = 25 * time.Millisecond
	t.Cleanup(func() { peerExchangeDialInterval = oldInterval })

	keyA, _ := ec.NewPrivateKey()
	keyB, _ := ec.NewPrivateKey()
	keyC, _ := ec.NewPrivateKey()
	mgrA := managerWithKey(t, keyA, ManagerConfig{PeerExchange: true, MaxExchangePeers: 2})
	mgrB := managerWithKey(t, keyB, ManagerConfig{})
	mgrC := managerWithKey(t, keyC, ManagerConfig{})
	defer mgrA.Stop()
	defer mgrB.Stop()
	defer mgrC.Stop()
	serverB := httptest.NewServer(mgrB.MeshHandler())
	serverC := httptest.NewServer(mgrC.MeshHandler())
	defer serverB.Close()
	defer serverC.Close()
	if err := mgrA.ConnectPeer(t.Context(), websocketURL(serverB.URL)); err != nil {
		t.Fatal(err)
	}
	waitForMesh(t, 5*time.Second, func() bool { return len(mgrB.Interests()) == 1 })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgrA.RunPeerExchange(ctx)
	heartbeat := &envelope.Envelope{
		Type: "data", Topic: "mesh:heartbeat", Timestamp: time.Now().Unix(), TTL: 300,
		Payload: `{"mesh_url":"` + websocketURL(serverC.URL) + `"}`,
	}
	heartbeat.Sign(keyC)
	mgrB.BroadcastEnvelope(heartbeat)
	identityC := fmt.Sprintf("%x", keyC.PubKey().Compressed())
	waitForMesh(t, 8*time.Second, func() bool { return mgrA.hasIdentityConnection(identityC) && mgrC.PeerCount() == 1 })
}

func TestPeerExchangeIdentityMismatchBacksOffWithoutAnnounce(t *testing.T) {
	allowLoopbackExchangeDial.Store(true)
	t.Cleanup(func() { allowLoopbackExchangeDial.Store(false) })
	oldInterval := peerExchangeDialInterval
	peerExchangeDialInterval = 20 * time.Millisecond
	t.Cleanup(func() { peerExchangeDialInterval = oldInterval })

	keyA, _ := ec.NewPrivateKey()
	keyX, _ := ec.NewPrivateKey()
	keyY, _ := ec.NewPrivateKey()
	mgrA := managerWithKey(t, keyA, ManagerConfig{PeerExchange: true, MaxExchangePeers: 1})
	mgrY := managerWithKey(t, keyY, ManagerConfig{})
	defer mgrA.Stop()
	defer mgrY.Stop()
	var requests atomic.Int32
	handler := mgrY.MeshHandler()
	serverY := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer serverY.Close()
	identityX := fmt.Sprintf("%x", keyX.PubKey().Compressed())
	mgrA.observePeerAdvert(&envelope.Envelope{
		Topic: "mesh:heartbeat", Pubkey: identityX, Timestamp: time.Now().Unix(),
		Payload: `{"mesh_url":"` + websocketURL(serverY.URL) + `"}`,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgrA.RunPeerExchange(ctx)
	waitForMesh(t, 5*time.Second, func() bool { return requests.Load() == 1 && candidateHasBackoff(mgrA, identityX) })
	requireConditionFor(t, 5*peerExchangeDialInterval, "identity mismatch retried or announced", func() bool {
		return requests.Load() == 1 && len(mgrY.Interests()) == 0
	})
	if requests.Load() != 1 || len(mgrY.Interests()) != 0 {
		t.Fatalf("mismatch requests=%d interests=%v", requests.Load(), mgrY.Interests())
	}
}

func TestPeerExchangeClosedModeDialsOnlyAllowedIdentity(t *testing.T) {
	oldInterval := peerExchangeDialInterval
	peerExchangeDialInterval = 20 * time.Millisecond
	t.Cleanup(func() { peerExchangeDialInterval = oldInterval })
	keyA, _ := ec.NewPrivateKey()
	keyAllowed, _ := ec.NewPrivateKey()
	keyOutside, _ := ec.NewPrivateKey()
	allowedIdentity := fmt.Sprintf("%x", keyAllowed.PubKey().Compressed())
	outIdentity := fmt.Sprintf("%x", keyOutside.PubKey().Compressed())
	mgrA := managerWithKey(t, keyA, ManagerConfig{
		PeerExchange: true, MaxExchangePeers: 2, AllowedPeers: []string{allowedIdentity},
	})
	mgrAllowed := managerWithKey(t, keyAllowed, ManagerConfig{})
	mgrOutside := managerWithKey(t, keyOutside, ManagerConfig{})
	defer mgrA.Stop()
	defer mgrAllowed.Stop()
	defer mgrOutside.Stop()
	serverAllowed := httptest.NewServer(mgrAllowed.MeshHandler())
	defer serverAllowed.Close()
	var outsideRequests atomic.Int32
	outHandler := mgrOutside.MeshHandler()
	serverOutside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideRequests.Add(1)
		outHandler.ServeHTTP(w, r)
	}))
	defer serverOutside.Close()
	for identity, endpoint := range map[string]string{
		allowedIdentity: websocketURL(serverAllowed.URL),
		outIdentity:     websocketURL(serverOutside.URL),
	} {
		mgrA.observePeerAdvert(&envelope.Envelope{
			Topic: "mesh:heartbeat", Pubkey: identity, Timestamp: time.Now().Unix(),
			Payload: `{"mesh_url":"` + endpoint + `"}`,
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgrA.RunPeerExchange(ctx)
	waitForMesh(t, 5*time.Second, func() bool { return mgrA.hasIdentityConnection(allowedIdentity) })
	requireConditionFor(t, 4*peerExchangeDialInterval, "outside allowlist peer was dialed", func() bool {
		return outsideRequests.Load() == 0 && !mgrA.hasIdentityConnection(outIdentity)
	})
	if outsideRequests.Load() != 0 || mgrA.hasIdentityConnection(outIdentity) {
		t.Fatalf("outside allowlist was dialed: requests=%d connected=%v", outsideRequests.Load(), mgrA.hasIdentityConnection(outIdentity))
	}
}

func managerWithKey(t *testing.T, key *ec.PrivateKey, cfg ManagerConfig) *Manager {
	t.Helper()
	walletLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := wallet.NewTestWallet(t, key, wallet.WithTestWalletLogger(walletLogger))
	cfg.Wallet = w
	cfg.IdentityKey = key
	cfg.LocalInterests = []string{""}
	return NewManager(cfg)
}

func websocketURL(httpURL string) string { return "ws" + httpURL[len("http"):] }

func peerForIdentity(m *Manager, identity string) *MeshPeer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peers[identity]
}

func directionForIdentity(m *Manager, identity string) string {
	peer := peerForIdentity(m, identity)
	if peer == nil {
		return ""
	}
	return peer.Direction
}

func candidateHasBackoff(m *Manager, identity string) bool {
	m.pex.mu.Lock()
	defer m.pex.mu.Unlock()
	candidate := m.pex.candidates[identity]
	return candidate != nil && !candidate.NextTry.IsZero()
}

func connectionPointers(m *Manager) map[*MeshPeer]struct{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peers := make(map[*MeshPeer]struct{}, len(m.peers))
	for _, peer := range m.peers {
		peers[peer] = struct{}{}
	}
	return peers
}

func sameConnectionPointers(a, b map[*MeshPeer]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for peer := range a {
		if _, ok := b[peer]; !ok {
			return false
		}
	}
	return true
}

func waitForMesh(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("mesh condition did not become true")
		case <-ticker.C:
		}
	}
}

func requireConditionFor(t *testing.T, duration time.Duration, failure string, stable func() bool) {
	t.Helper()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !stable() {
			t.Fatal(failure)
		}
		select {
		case <-deadline.C:
			return
		case <-ticker.C:
		}
	}
}

func broadcastTestEnvelope(t *testing.T, manager *Manager, key *ec.PrivateKey, payload string) {
	t.Helper()
	env := &envelope.Envelope{Type: "data", Topic: "test:flow", Payload: payload, Timestamp: time.Now().Unix(), TTL: 60}
	env.Sign(key)
	manager.BroadcastEnvelope(env)
}

func waitForPayload(t *testing.T, received <-chan string, want string) {
	t.Helper()
	select {
	case got := <-received:
		if got != want {
			t.Fatalf("payload = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}
