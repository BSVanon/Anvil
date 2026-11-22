package gossip

// removePeer removes either one exact socket (when passed its process-unique
// key) or every live socket for an authenticated identity. Selection and
// detachment happen in one critical section with duplicate binding.
func (m *Manager) removePeer(origKey string) {
	m.removePeerWithReason(origKey, "")
}

func (m *Manager) removePeerWithReason(origKey, reason string) {
	m.mu.Lock()
	var exact *MeshPeer
	for _, peer := range m.peers {
		if peer.origKey == origKey {
			exact = peer
			break
		}
	}
	if exact != nil {
		if exact.closed {
			m.mu.Unlock()
			return
		}
		exact.closed = true
		exact.closeReason = reason
		m.deletePeerPointerLocked(exact, "")
		identity := peerIdentity(exact)
		m.cleanupIdentityLocked(identity)
		peerCount := len(m.peers)
		m.mu.Unlock()
		m.clearPeerRateIfDisconnected(identity)
		m.closeDetachedPeer(exact, reason, peerCount)
		return
	}

	// No connection key matched, so this is an identity-scoped removal.
	// Record the current creation sequence before detaching: any socket that
	// already existed but was still authenticating is rejected when it later
	// attempts to bind this identity.
	m.identityRemovalSeq[origKey] = m.connSeq.Load()
	unique := make(map[*MeshPeer]struct{})
	for key, peer := range m.peers {
		if key == origKey || peerIdentity(peer) == origKey {
			unique[peer] = struct{}{}
		}
	}
	for peer := range unique {
		m.deletePeerPointerLocked(peer, "")
		peer.closed = true
		peer.closeReason = reason
	}
	delete(m.interests, origKey)
	delete(m.duplicateSafePeers, origKey)
	peerCount := len(m.peers)
	m.mu.Unlock()

	m.peerRateMu.Lock()
	delete(m.peerRates, origKey)
	m.peerRateMu.Unlock()
	for peer := range unique {
		m.closeDetachedPeer(peer, reason, peerCount)
	}
}
