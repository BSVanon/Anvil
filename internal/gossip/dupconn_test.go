package gossip

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestDuplicateConnectionKeepsDialFromLowerIdentity(t *testing.T) {
	remote := duplicateRemoteKey(t)
	identity := fmt.Sprintf("%x", remote.Compressed())
	tests := []struct {
		name          string
		localIdentity string
		existingDir   string
		candidateDir  string
		candidateSeed bool
		candidateWins bool
	}{
		{"lower local identity keeps outbound", "00", "inbound", "outbound", false, true},
		{"higher local identity keeps inbound", "ff", "inbound", "outbound", false, false},
		{"higher local identity keeps inbound over reciprocal seed", "ff", "inbound", "outbound", true, false},
		{"two outbound dials keep existing", "00", "outbound", "outbound", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := NewManager(ManagerConfig{})
			m.connLog = &ConnectionLog{maxRecent: 10}
			m.localIdentity = test.localIdentity
			var existingClosed, candidateClosed atomic.Int32
			existing := &MeshPeer{IdentityPK: remote, Direction: test.existingDir, origKey: "existing", closeFunc: func() error { existingClosed.Add(1); return nil }}
			candidate := &MeshPeer{Direction: test.candidateDir, seed: test.candidateSeed, origKey: "candidate", closeFunc: func() error { candidateClosed.Add(1); return nil }}
			m.peers[identity] = existing
			m.peers[candidate.origKey] = candidate
			m.duplicateSafePeers[identity] = struct{}{}
			m.interests[identity] = []string{"topic:"}
			m.peerRates[identity] = &peerRate{tokens: 3}

			_, err := m.bindPeerIdentity(candidate, remote, true)
			if test.candidateWins && err != nil {
				t.Fatalf("candidate should win: %v", err)
			}
			if !test.candidateWins && !errors.Is(err, errDuplicateConnection) {
				t.Fatalf("candidate should lose with duplicate error: %v", err)
			}
			want := existing
			if test.candidateWins {
				want = candidate
			}
			if got := m.peers[identity]; got != want {
				t.Fatalf("identity points to %p, want %p", got, want)
			}
			if len(m.peers) != 1 {
				t.Fatalf("peer map has %d entries after resolution", len(m.peers))
			}
			if len(m.interests[identity]) != 1 || m.peerRates[identity] == nil {
				t.Fatal("duplicate resolution removed identity state")
			}
			events := m.RecentConnections(1)
			if len(events) != 1 || events[0].Reason != "duplicate_connection" {
				t.Fatalf("duplicate event = %+v", events)
			}
			if test.candidateWins {
				if existingClosed.Load() != 1 || candidateClosed.Load() != 0 {
					t.Fatalf("close counts existing=%d candidate=%d", existingClosed.Load(), candidateClosed.Load())
				}
			} else if candidateClosed.Load() != 1 || existingClosed.Load() != 0 {
				t.Fatalf("close counts existing=%d candidate=%d", existingClosed.Load(), candidateClosed.Load())
			}
		})
	}
}

func TestLoserCleanupCannotRemoveKeptIdentity(t *testing.T) {
	m := NewManager(ManagerConfig{})
	m.localIdentity = "ff"
	remote := duplicateRemoteKey(t)
	identity := fmt.Sprintf("%x", remote.Compressed())
	existing := &MeshPeer{IdentityPK: remote, Direction: "inbound", origKey: "kept"}
	loser := &MeshPeer{Direction: "outbound", origKey: "loser"}
	m.peers[identity] = existing
	m.peers[loser.origKey] = loser
	m.duplicateSafePeers[identity] = struct{}{}
	if _, err := m.bindPeerIdentity(loser, remote, true); !errors.Is(err, errDuplicateConnection) {
		t.Fatalf("bind error = %v", err)
	}
	m.removePeerWithReason(loser.origKey, "transport_closed")
	if m.peers[identity] != existing {
		t.Fatal("late loser cleanup removed the kept identity")
	}
	m.removePeerWithReason(identity, "slashed")
	if m.peers[identity] != nil {
		t.Fatal("identity removal did not remove the kept connection")
	}
}

func TestDuplicateConnectionWaitsForExactRemovalCapability(t *testing.T) {
	m := NewManager(ManagerConfig{})
	m.localIdentity = "00"
	remote := duplicateRemoteKey(t)
	identity := fmt.Sprintf("%x", remote.Compressed())
	var existingClosed, candidateClosed atomic.Int32
	existing := &MeshPeer{
		IdentityPK: remote, Direction: "inbound", origKey: "existing",
		closeFunc: func() error { existingClosed.Add(1); return nil },
	}
	candidate := &MeshPeer{
		Direction: "outbound", origKey: "candidate",
		closeFunc: func() error { candidateClosed.Add(1); return nil },
	}
	m.peers[identity] = existing
	m.peers[candidate.origKey] = candidate

	if _, err := m.bindPeerIdentity(candidate, remote, true); err != nil {
		t.Fatalf("bind without negotiated capability: %v", err)
	}
	if existingClosed.Load() != 0 || candidateClosed.Load() != 0 {
		t.Fatalf("mixed-version duplicate was closed: existing=%d candidate=%d",
			existingClosed.Load(), candidateClosed.Load())
	}
	if len(m.peers) != 2 || m.peers[identity] != candidate || m.peers[existing.origKey] != existing {
		t.Fatalf("compatibility sockets were not retained: peers=%v", m.peers)
	}
}

func TestConfiguredSeedReplacesLearnedConnectionForSameIdentity(t *testing.T) {
	m := NewManager(ManagerConfig{})
	remote := duplicateRemoteKey(t)
	identity := fmt.Sprintf("%x", remote.Compressed())
	var exchangeClosed atomic.Int32
	exchange := &MeshPeer{
		IdentityPK: remote, Direction: "outbound", origKey: "exchange", exchange: true,
		closeFunc: func() error { exchangeClosed.Add(1); return nil },
	}
	seed := &MeshPeer{Direction: "outbound", origKey: "seed", seed: true}
	m.peers[identity] = exchange
	m.peers[seed.origKey] = seed
	m.duplicateSafePeers[identity] = struct{}{}

	if _, err := m.bindPeerIdentity(seed, remote, true); err != nil {
		t.Fatalf("bind configured seed: %v", err)
	}
	if m.peers[identity] != seed || exchangeClosed.Load() != 1 {
		t.Fatalf("configured seed did not replace exchange peer: kept=%p seed=%p closes=%d",
			m.peers[identity], seed, exchangeClosed.Load())
	}
}

func TestIdentityRemovalCoversReplacementAndAuthenticatingSocket(t *testing.T) {
	m := NewManager(ManagerConfig{})
	remote := duplicateRemoteKey(t)
	identity := fmt.Sprintf("%x", remote.Compressed())
	_, firstID := m.nextConnection("inbound")
	pendingKey, pendingID := m.nextConnection("inbound")
	removeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	var liveClosed, replacementClosed, pendingClosed atomic.Int32
	live := &MeshPeer{
		IdentityPK: remote, origKey: "live", connectionID: firstID,
		closeFunc: func() error {
			liveClosed.Add(1)
			close(removeStarted)
			<-releaseClose
			return nil
		},
	}
	replacement := &MeshPeer{
		IdentityPK: remote, origKey: "replacement", connectionID: firstID,
		closeFunc: func() error { replacementClosed.Add(1); return nil },
	}
	pending := &MeshPeer{
		origKey: pendingKey, connectionID: pendingID,
		closeFunc: func() error { pendingClosed.Add(1); return nil },
	}
	m.peers[identity] = live
	m.peers[replacement.origKey] = replacement
	m.peers[pending.origKey] = pending

	removed := make(chan struct{})
	go func() {
		m.removePeerWithReason(identity, "slashed")
		close(removed)
	}()
	<-removeStarted

	bindDone := make(chan error, 1)
	go func() {
		_, err := m.bindPeerIdentity(pending, remote, true)
		bindDone <- err
	}()
	if err := <-bindDone; !errors.Is(err, errIdentityRemoved) {
		t.Fatalf("authenticating socket bind error = %v, want errIdentityRemoved", err)
	}
	close(releaseClose)
	<-removed

	if liveClosed.Load() != 1 || replacementClosed.Load() != 1 || pendingClosed.Load() != 1 {
		t.Fatalf("close counts live=%d replacement=%d pending=%d, want all 1",
			liveClosed.Load(), replacementClosed.Load(), pendingClosed.Load())
	}
	if len(m.peers) != 0 {
		t.Fatalf("identity removal left %d socket(s)", len(m.peers))
	}
}

func TestSelfConnectionIsClosedBeforeBinding(t *testing.T) {
	m := NewManager(ManagerConfig{})
	self := duplicateRemoteKey(t)
	m.localIdentity = fmt.Sprintf("%x", self.Compressed())
	var closed atomic.Int32
	peer := &MeshPeer{Direction: "inbound", origKey: "self", closeFunc: func() error { closed.Add(1); return nil }}
	m.peers[peer.origKey] = peer
	if _, err := m.bindPeerIdentity(peer, self, true); !errors.Is(err, errSelfConnection) {
		t.Fatalf("bind error = %v", err)
	}
	if len(m.peers) != 0 || closed.Load() != 1 {
		t.Fatalf("self connection remained: peers=%d closes=%d", len(m.peers), closed.Load())
	}
}

func duplicateRemoteKey(t *testing.T) *ec.PublicKey {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.PubKey()
}
