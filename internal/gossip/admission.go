package gossip

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// admittedSendPeer is an immutable send snapshot. Application fan-outs use
// these snapshots so no network operation runs under Manager.mu and no socket
// receives application data before identity, allowlist, and bond admission.
type admittedSendPeer struct {
	identity   string
	peer       *auth.Peer
	identityPK *ec.PublicKey
}

func (m *Manager) admitPeer(target *MeshPeer, bondSats int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if target.closed || !m.peerMappedLocked(target) || target.IdentityPK == nil {
		return false
	}
	target.BondSats = bondSats
	target.bondChecked = true
	target.admitted = true
	return true
}

func admittedPrimaryLocked(key string, peer *MeshPeer) bool {
	return peer != nil && peer.Peer != nil && peer.IdentityPK != nil &&
		peer.admitted && !peer.closed && key == fmt.Sprintf("%x", peer.IdentityPK.Compressed())
}

func (m *Manager) admittedPeer(identity string) (admittedSendPeer, bool) {
	m.mu.RLock()
	peer := m.peers[identity]
	if !admittedPrimaryLocked(identity, peer) {
		m.mu.RUnlock()
		return admittedSendPeer{}, false
	}
	target := admittedSendPeer{identity: identity, peer: peer.Peer, identityPK: peer.IdentityPK}
	m.mu.RUnlock()
	return target, true
}

func (m *Manager) admittedPeers(excludeIdentity string) []admittedSendPeer {
	m.mu.RLock()
	peers := make([]admittedSendPeer, 0, len(m.peers))
	for identity, peer := range m.peers {
		if identity == excludeIdentity || !admittedPrimaryLocked(identity, peer) {
			continue
		}
		peers = append(peers, admittedSendPeer{
			identity: identity, peer: peer.Peer, identityPK: peer.IdentityPK,
		})
	}
	m.mu.RUnlock()
	return peers
}
