package gossip

import (
	"encoding/json"
	"errors"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

var (
	errDuplicateConnection = errors.New("duplicate mesh connection")
	errSelfConnection      = errors.New("mesh connection resolved to this node")
	errIdentityMismatch    = errors.New("mesh peer identity mismatch")
	errIdentityRemoved     = errors.New("mesh identity removed while connection was authenticating")
	errBondRejected        = errors.New("mesh peer bond rejected")
	errConnectionClosed    = errors.New("mesh connection already closed")
)

const exactRemovalCapability = "exact_connection_removal_v1"

func (m *Manager) nextConnection(direction string) (string, uint64) {
	id := m.connSeq.Add(1)
	return fmt.Sprintf("%s-%d", direction, id), id
}

// noteDuplicateCapability records an explicit wire capability before identity
// binding decides whether it is safe to close a reciprocal socket. Older peers
// ignore the added topics field and never advertise it, so mixed-version pairs
// retain both sockets instead of triggering the old exact-removal defect.
func (m *Manager) noteDuplicateCapability(identity string, payload []byte) {
	msg, err := Decode(payload)
	if err != nil || msg.Type != MsgTopics {
		return
	}
	var topics TopicsPayload
	if json.Unmarshal(msg.Data, &topics) != nil {
		return
	}
	for _, capability := range topics.Capabilities {
		if capability == exactRemovalCapability {
			m.mu.Lock()
			m.duplicateSafePeers[identity] = struct{}{}
			m.mu.Unlock()
			return
		}
	}
}

// bindPeerIdentity assigns an authenticated identity to one socket. When the
// remote has advertised exact-removal support, reciprocal sockets converge on
// the deterministic winner. Until then both sockets remain live for rolling
// compatibility, with only the preferred socket stored under the identity key.
func (m *Manager) bindPeerIdentity(candidate *MeshPeer, identityPK *ec.PublicKey) (bool, error) {
	identity := fmt.Sprintf("%x", identityPK.Compressed())
	if identity == m.localIdentity && identity != "" {
		m.detachPeer(candidate, "self_connection")
		return false, errSelfConnection
	}

	var losers []*MeshPeer
	m.mu.Lock()
	if candidate.closed {
		m.mu.Unlock()
		return false, errConnectionClosed
	}
	if candidate.connectionID != 0 && candidate.connectionID <= m.identityRemovalSeq[identity] {
		m.deletePeerPointerLocked(candidate, "")
		candidate.closed = true
		peerCount := len(m.peers)
		m.mu.Unlock()
		m.closeDetachedPeer(candidate, "identity_removed", peerCount)
		return false, errIdentityRemoved
	}
	if candidate.IdentityPK != nil && fmt.Sprintf("%x", candidate.IdentityPK.Compressed()) != identity {
		m.mu.Unlock()
		return false, errIdentityMismatch
	}
	firstIdentity := candidate.IdentityPK == nil
	candidate.IdentityPK = identityPK
	existing := m.peers[identity]
	if existing == nil || existing == candidate {
		m.peers[identity] = candidate
		m.deletePeerPointerLocked(candidate, identity)
		m.mu.Unlock()
		return firstIdentity, nil
	}

	_, safe := m.duplicateSafePeers[identity]
	if !safe || m.disableDuplicateConvergence {
		if m.candidateWinsDuplicate(existing, candidate, identity) {
			m.peers[existing.origKey] = existing
			m.peers[identity] = candidate
			m.deletePeerPointerLocked(candidate, identity)
		} else if !m.peerMappedLocked(candidate) {
			m.peers[candidate.origKey] = candidate
		}
		m.mu.Unlock()
		return firstIdentity, nil
	}

	kept := existing
	if m.candidateWinsDuplicate(existing, candidate, identity) {
		kept = candidate
	}
	unique := make(map[*MeshPeer]struct{})
	for _, peer := range m.peers {
		if peerIdentity(peer) == identity && peer != kept {
			unique[peer] = struct{}{}
		}
	}
	if candidate != kept {
		unique[candidate] = struct{}{}
	}
	for peer := range unique {
		m.deletePeerPointerLocked(peer, "")
		peer.closed = true
		losers = append(losers, peer)
	}
	m.peers[identity] = kept
	m.deletePeerPointerLocked(kept, identity)
	peerCount := len(m.peers)
	m.mu.Unlock()

	for _, loser := range losers {
		m.closeDetachedPeer(loser, "duplicate_connection", peerCount)
	}
	if target, ok := m.admittedPeer(identity); kept == existing && ok && target.peer == kept.Peer {
		go func() { _ = m.announceInterests(target.peer) }()
	}
	if candidate != kept {
		return false, errDuplicateConnection
	}
	return firstIdentity, nil
}

func (m *Manager) candidateWinsDuplicate(existing, candidate *MeshPeer, identity string) bool {
	if existing.seed && candidate.exchange {
		return false
	}
	if candidate.seed && existing.exchange {
		return true
	}
	if existing.Direction == candidate.Direction {
		return false
	}
	preferOutbound := m.localIdentity != "" && m.localIdentity < identity
	return (preferOutbound && candidate.Direction == "outbound") ||
		(!preferOutbound && candidate.Direction == "inbound")
}

func peerIdentity(peer *MeshPeer) string {
	if peer == nil || peer.IdentityPK == nil {
		return ""
	}
	return fmt.Sprintf("%x", peer.IdentityPK.Compressed())
}

func (m *Manager) peerMappedLocked(target *MeshPeer) bool {
	for _, peer := range m.peers {
		if peer == target {
			return true
		}
	}
	return false
}

// deletePeerPointerLocked removes all aliases for target except keepKey.
func (m *Manager) deletePeerPointerLocked(target *MeshPeer, keepKey string) {
	for key, peer := range m.peers {
		if key != keepKey && peer == target {
			delete(m.peers, key)
		}
	}
}

func (m *Manager) detachPeer(target *MeshPeer, reason string) {
	m.mu.Lock()
	if target.closed {
		m.mu.Unlock()
		return
	}
	target.closed = true
	m.deletePeerPointerLocked(target, "")
	identity := peerIdentity(target)
	m.cleanupIdentityLocked(identity)
	peerCount := len(m.peers)
	m.mu.Unlock()
	m.clearPeerRateIfDisconnected(identity)
	m.closeDetachedPeer(target, reason, peerCount)
}

// cleanupIdentityLocked promotes a compatibility socket when the primary
// closes. Identity-scoped state is removed only after the final socket goes.
func (m *Manager) cleanupIdentityLocked(identity string) {
	if identity == "" {
		return
	}
	if m.peers[identity] == nil {
		for key, peer := range m.peers {
			if !peer.closed && peerIdentity(peer) == identity {
				m.peers[identity] = peer
				if key != identity {
					delete(m.peers, key)
				}
				return
			}
		}
	}
	if m.peers[identity] == nil {
		delete(m.interests, identity)
		delete(m.duplicateSafePeers, identity)
	}
}

func (m *Manager) clearPeerRateIfDisconnected(identity string) {
	if identity == "" || m.hasIdentityConnection(identity) {
		return
	}
	m.peerRateMu.Lock()
	delete(m.peerRates, identity)
	m.peerRateMu.Unlock()
}

func (m *Manager) removeMeshPeerWithReason(target *MeshPeer, reason string) {
	m.detachPeer(target, reason)
}

func (m *Manager) closeDetachedPeer(peer *MeshPeer, reason string, peerCount int) {
	if peer == nil {
		return
	}
	event := m.disconnectEventForPeer(peer, reason, peerCount)
	if peer.Peer != nil {
		_ = peer.Peer.Stop()
	}
	if peer.closeFunc != nil {
		_ = peer.closeFunc()
	}
	m.recordConnectionEvent(event)
}

func (m *Manager) hasIdentityConnection(identity string) bool {
	m.mu.RLock()
	peer := m.peers[identity]
	connected := peer != nil && peer.admitted && peerIdentity(peer) == identity
	m.mu.RUnlock()
	return connected
}

func (m *Manager) hasPeerConnection(target *MeshPeer) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.peerMappedLocked(target)
}
