package gossip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func TestAdvertiseURLValidationBoundsAndShape(t *testing.T) {
	valid := []string{"ws://node.example", "wss://node.example/mesh", "ws://[2001:db8::1]:8333/mesh"}
	for _, raw := range valid {
		if err := validateAdvertiseURL(raw); err != nil {
			t.Fatalf("validateAdvertiseURL(%q): %v", raw, err)
		}
	}
	invalid := []string{
		"", "http://node.example", "ws:///mesh", "ws://user@node.example",
		"ws://node.example?x=1", "ws://node.example#x", "ws://" + strings.Repeat("a", 513),
	}
	for _, raw := range invalid {
		if err := validateAdvertiseURL(raw); err == nil {
			t.Fatalf("validateAdvertiseURL(%q) accepted invalid value", raw)
		}
	}
}

func TestExchangeAddressGuardRejectsNonPublicAddresses(t *testing.T) {
	tests := []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
		"172.16.0.1", "192.168.0.1", "224.0.0.1", "::", "::1", "fc00::1",
		"fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:100.64.0.1",
	}
	for _, raw := range tests {
		if !isUnsafeExchangeIP(net.ParseIP(raw)) {
			t.Errorf("%s was not classified as unsafe", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"} {
		if isUnsafeExchangeIP(net.ParseIP(raw)) {
			t.Errorf("%s was classified as unsafe", raw)
		}
	}
}

func TestExchangeControlHookRefusesLoopbackUnlessTestSwitchIsSet(t *testing.T) {
	allowLoopbackExchangeDial.Store(false)
	t.Cleanup(func() { allowLoopbackExchangeDial.Store(false) })
	if err := exchangeDialControl("tcp", "127.0.0.1:8333", nil); err == nil {
		t.Fatal("loopback address was accepted")
	}
	allowLoopbackExchangeDial.Store(true)
	if err := exchangeDialControl("tcp", "127.0.0.1:8333", nil); err != nil {
		t.Fatalf("test loopback switch did not allow loopback: %v", err)
	}
}

func TestOpenExchangeDialRefusesLoopbackBeforeConnecting(t *testing.T) {
	allowLoopbackExchangeDial.Store(false)
	t.Cleanup(func() { allowLoopbackExchangeDial.Store(false) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()

	_, err = newWSTransportAdapter("ws://"+listener.Addr().String(), time.Second, true)
	if err == nil || !strings.Contains(err.Error(), "peer exchange refused non-public address") {
		t.Fatalf("exchange dial error = %v, want non-public address refusal", err)
	}
	_ = listener.Close()
	<-acceptDone
	if got := accepted.Load(); got != 0 {
		t.Fatalf("loopback listener accepted %d connections, want zero", got)
	}
}

func TestAdvertiseCandidateDerivation(t *testing.T) {
	tests := []struct {
		name           string
		public, listen string
		tls, closed    bool
		want           []string
	}{
		{"https with proxy and plain listener", "https://node.example", "0.0.0.0:8333", false, false, []string{"wss://node.example/mesh", "ws://node.example:8333"}},
		{"https with tls listener", "https://node.example", ":8443", true, false, []string{"wss://node.example/mesh", "wss://node.example:8443"}},
		{"http", "http://node.example", ":8333", false, false, []string{"ws://node.example:8333"}},
		{"private literal", "https://192.168.1.2", ":8333", false, false, nil},
		{"localhost", "http://localhost", ":8333", false, false, nil},
		{"empty listen", "https://node.example", "", false, false, nil},
		{"closed mode", "https://node.example", ":8333", false, true, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := deriveAdvertiseCandidates(test.public, test.listen, test.tls, test.closed)
			if strings.Join(got, "|") != strings.Join(test.want, "|") {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestAdvertiserSelectsFirstVerifiedCandidate(t *testing.T) {
	var checked []string
	got := verifyAdvertiseCandidates(context.Background(), []string{"wss://first/mesh", "ws://second:8333", "ws://third:8333"},
		func(_ context.Context, candidate string) error {
			checked = append(checked, candidate)
			if strings.Contains(candidate, "second") {
				return nil
			}
			return errors.New("unreachable")
		})
	if got != "ws://second:8333" || len(checked) != 2 {
		t.Fatalf("selected %q after %v", got, checked)
	}
}

func TestAdvertiserInitialStateControlsHeartbeatSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	configured := NewManager(ManagerConfig{PeerExchange: true, MaxExchangePeers: 8})
	configured.StartPeerExchangeAdvertiser(ctx, PeerAdvertiseConfig{ExplicitURL: "wss://self.example/mesh"})
	if got := configured.PeerExchangeAdvertisedURL(); got != "wss://self.example/mesh" {
		t.Fatalf("configured heartbeat source = %q", got)
	}
	if state := configured.PeerExchangeStatus().AdvertiseState; state != "configured" {
		t.Fatalf("configured state = %q", state)
	}

	derived := NewManager(ManagerConfig{PeerExchange: true, MaxExchangePeers: 8})
	derived.StartPeerExchangeAdvertiser(ctx, PeerAdvertiseConfig{PublicURL: "https://self.example", Listen: ":8333"})
	if got := derived.PeerExchangeAdvertisedURL(); got != "" {
		t.Fatalf("unverified derived heartbeat source = %q", got)
	}
	if state := derived.PeerExchangeStatus().AdvertiseState; state != "unverified" {
		t.Fatalf("derived state = %q", state)
	}
}

func TestHeartbeatAdvertisementsAreFreshNewestAndBounded(t *testing.T) {
	m := NewManager(ManagerConfig{PeerExchange: true, MaxExchangePeers: 8})
	now := time.Now()
	add := func(identity, meshURL string, timestamp int64) {
		m.observePeerAdvert(&envelope.Envelope{Topic: "mesh:heartbeat", Pubkey: identity, Payload: `{"mesh_url":"` + meshURL + `"}`, Timestamp: timestamp})
	}
	add("02stale", "wss://stale.example/mesh", now.Add(-time.Hour-time.Second).Unix())
	add("02future", "wss://future.example/mesh", now.Add(10*time.Minute+time.Second).Unix())
	add("02empty", "", now.Unix())
	m.observePeerAdvert(&envelope.Envelope{Topic: "mesh:heartbeat", Pubkey: "02absent", Payload: `{}`, Timestamp: now.Unix()})
	if len(m.pex.candidates) != 0 {
		t.Fatalf("invalid advertisements added %d candidates", len(m.pex.candidates))
	}
	add("02peer", "wss://old.example/mesh", now.Add(-time.Minute).Unix())
	add("02peer", "wss://older.example/mesh", now.Add(-2*time.Minute).Unix())
	add("02peer", "wss://new.example/mesh", now.Unix())
	if got := m.pex.candidates["02peer"].URL; got != "wss://new.example/mesh" {
		t.Fatalf("newest URL = %q", got)
	}

	m.pex.candidates = make(map[string]*peerCandidate, maxPeerExchangeCandidates)
	for i := 0; i < maxPeerExchangeCandidates; i++ {
		identity := "peer-" + time.Unix(int64(i), 0).Format("150405.000000000")
		m.pex.candidates[identity] = &peerCandidate{Identity: identity, AdvertisedAt: now.Add(-30 * time.Minute)}
	}
	m.pex.candidates["oldest"] = &peerCandidate{Identity: "oldest", AdvertisedAt: now.Add(-59 * time.Minute)}
	delete(m.pex.candidates, "peer-"+time.Unix(0, 0).Format("150405.000000000"))
	add("02new", "wss://newest.example/mesh", now.Unix())
	if len(m.pex.candidates) != maxPeerExchangeCandidates || m.pex.candidates["oldest"] != nil {
		t.Fatalf("candidate cap/oldest eviction failed: count=%d oldest=%v", len(m.pex.candidates), m.pex.candidates["oldest"] != nil)
	}
}

func TestExchangeSelectionHonorsAllowlistSeedAndCaps(t *testing.T) {
	m := NewManager(ManagerConfig{
		PeerExchange: true, MaxExchangePeers: 1, AllowedPeers: []string{"02allowed"},
		SeedURLs: []string{"wss://seed.example/mesh"},
	})
	now := time.Now()
	for identity, endpoint := range map[string]string{
		"02allowed": "wss://allowed.example/mesh",
		"02outside": "wss://outside.example/mesh",
		"02seed":    "wss://seed.example/mesh",
	} {
		m.pex.candidates[identity] = &peerCandidate{Identity: identity, URL: endpoint, AdvertisedAt: now}
	}
	selected := m.exchangeCandidates(now)
	if len(selected) != 1 || selected[0].Identity != "02allowed" {
		t.Fatalf("selected %+v", selected)
	}
	m.pex.mu.Lock()
	m.pex.candidates[selected[0].Identity].Dialing = false
	m.pex.mu.Unlock()
	liveKey := mustPublicKey(t)
	liveIdentity := fmt.Sprintf("%x", liveKey.Compressed())
	m.peers[liveIdentity] = &MeshPeer{Peer: &auth.Peer{}, IdentityPK: liveKey, admitted: true, exchange: true}
	if got := m.exchangeCandidates(now); len(got) != 0 {
		t.Fatalf("selected %d candidates with live exchange at cap", len(got))
	}
	delete(m.peers, liveIdentity)
	m.pex.mu.Lock()
	m.pex.candidates["02allowed"].Dialing = true
	m.pex.mu.Unlock()
	if got := m.exchangeCandidates(now); len(got) != 0 {
		t.Fatalf("selected %d candidates with exchange dial in flight at cap", len(got))
	}

	open := NewManager(ManagerConfig{PeerExchange: true, MaxExchangePeers: 8})
	for _, identity := range []string{"02one", "02two", "02three", "02configuredseed"} {
		open.pex.candidates[identity] = &peerCandidate{Identity: identity, URL: "wss://" + identity + ".example/mesh", AdvertisedAt: now}
	}
	open.noteSeedIdentity("02configuredseed")
	if got := open.exchangeCandidates(now); len(got) != 2 || got[0].Identity == "02configuredseed" || got[1].Identity == "02configuredseed" {
		t.Fatalf("one tick selected %d candidates, want 2", len(got))
	}
}

func TestPeerExchangeDisabledLearnsDialsAndAdvertisesNothing(t *testing.T) {
	m := NewManager(ManagerConfig{PeerExchange: false, MaxExchangePeers: 8})
	m.observePeerAdvert(&envelope.Envelope{
		Topic: "mesh:heartbeat", Pubkey: "02peer", Timestamp: time.Now().Unix(),
		Payload: `{"mesh_url":"wss://peer.example/mesh"}`,
	})
	m.RunPeerExchange(context.Background())
	m.RunPeerExchangeAdvertiser(context.Background(), PeerAdvertiseConfig{ExplicitURL: "wss://self.example/mesh"})
	status := m.PeerExchangeStatus()
	if status.Enabled || status.Candidates != 0 || status.ExchangePeers != 0 || status.AdvertisedURL != "" || status.AdvertiseState != "off" {
		t.Fatalf("disabled status = %+v", status)
	}
}

func mustPublicKey(t *testing.T) *ec.PublicKey {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.PubKey()
}
