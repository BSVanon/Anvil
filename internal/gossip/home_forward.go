package gossip

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/BSVanon/Anvil/internal/messaging"
	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

const maxConcurrentHomeSends = 16

// peerSendTarget is an immutable routing snapshot. It deliberately contains no
// *MeshPeer, endpoint, or map key: only the authenticated identity and the
// connection objects needed for one send.
type peerSendTarget struct {
	peer       *auth.Peer
	identityPK *ec.PublicKey
	identity   string
}

func containsHome(homes []string, identity string) bool {
	for _, home := range homes {
		if home == identity {
			return true
		}
	}
	return false
}

func (m *Manager) snapshotAllowedPeers(source string, identities map[string]struct{}, requireCapability bool) []peerSendTarget {
	source = strings.ToLower(source)
	own := m.ownIdentity()
	m.mu.RLock()
	targets := make([]peerSendTarget, 0, len(m.peers))
	for identity, peer := range m.peers {
		if !admittedPrimaryLocked(identity, peer) || identity == source || identity == own {
			continue
		}
		if m.allowlist == nil || !m.allowlist.allows(identity) || requireCapability && peer.privateHomeVersion < privateHomeProtocolVersion {
			continue
		}
		if identities != nil {
			if _, ok := identities[identity]; !ok {
				continue
			}
		}
		targets = append(targets, peerSendTarget{peer: peer.Peer, identityPK: peer.IdentityPK, identity: identity})
	}
	m.mu.RUnlock()
	return targets
}

func (m *Manager) targetForIdentity(identity string) (peerSendTarget, bool) {
	identity = strings.ToLower(identity)
	m.mu.RLock()
	peer, ok := m.peers[identity]
	if ok {
		ok = admittedPrimaryLocked(identity, peer)
	}
	var target peerSendTarget
	if ok {
		target = peerSendTarget{peer: peer.Peer, identityPK: peer.IdentityPK, identity: identity}
	}
	m.mu.RUnlock()
	return target, ok
}

func (m *Manager) targetForPeer(authPeer *auth.Peer) (peerSendTarget, bool) {
	if authPeer == nil {
		return peerSendTarget{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for identity, peer := range m.peers {
		if peer.Peer == authPeer && admittedPrimaryLocked(identity, peer) {
			return peerSendTarget{peer: peer.Peer, identityPK: peer.IdentityPK, identity: identity}, true
		}
	}
	return peerSendTarget{}, false
}

func (m *Manager) forEachTargetConcurrent(targets []peerSendTarget, fn func(peerSendTarget)) {
	if len(targets) == 0 {
		return
	}
	workers := min(len(targets), maxConcurrentHomeSends)
	jobs := make(chan peerSendTarget)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for target := range jobs {
				fn(target)
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wait.Wait()
}

func (m *Manager) sendPayloadToTargets(payload []byte, targets []peerSendTarget) int {
	var sent atomic.Int64
	m.forEachTargetConcurrent(targets, func(target peerSendTarget) {
		if target.peer.ToPeer(context.Background(), payload, target.identityPK, 5000) == nil {
			sent.Add(1)
		}
	})
	return int(sent.Load())
}

func (m *Manager) sendToAllowedPeers(payload []byte, source string, identities map[string]struct{}) int {
	return m.sendPayloadToTargets(payload, m.snapshotAllowedPeers(source, identities, false))
}

// CanApplyPrivateHomeClaim rejects a local claim when one of its currently
// connected named gateways has not negotiated private-home protocol support.
// Disconnected gateways remain eligible; their capability is checked when they
// next connect, and forwarding never treats them as ready before application.
func (m *Manager) CanApplyPrivateHomeClaim(homes []string) bool {
	own := m.ownIdentity()
	wanted := make(map[string]struct{}, len(homes))
	for _, home := range homes {
		home = strings.ToLower(home)
		if home != own {
			wanted[home] = struct{}{}
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for identity, peer := range m.peers {
		if _, named := wanted[identity]; named && admittedPrimaryLocked(identity, peer) && peer.privateHomeVersion < privateHomeProtocolVersion {
			return false
		}
	}
	return true
}

// selectedForwardPeers targets capable named homes that acknowledged the
// relevant claim. If no named home is ready, the fallback includes only other
// admitted, capable peers that acknowledged the same claim.
func (m *Manager) selectedForwardPeers(recipient, source string) []peerSendTarget {
	var homes []string
	claimVersion := int64(0)
	if m.messagingPolicy.PrivateHomes != nil {
		if claim, ok, err := m.messagingPolicy.PrivateHomes.Current(recipient); err == nil && ok {
			homes, claimVersion = claim.Homes, claim.IssuedAt
			m.pruneAppliedHomeRecords([]messaging.PrivateHomeRecord{claim})
		} else if err == nil {
			m.dropAppliedHomeClaim(recipient)
		}
	}
	source, own := strings.ToLower(source), m.ownIdentity()
	m.mu.RLock()
	ready := make([]peerSendTarget, 0, len(m.peers))
	namedConnected := false
	for identity, peer := range m.peers {
		if !admittedPrimaryLocked(identity, peer) || identity == source || identity == own {
			continue
		}
		if !m.peerAllowedForForward(identity) {
			continue
		}
		if claimVersion > 0 {
			if m.allowlist == nil || !m.allowlist.enabled() || !m.allowlist.allows(identity) {
				continue
			}
			if peer.privateHomeVersion < privateHomeProtocolVersion || peer.appliedHomeClaims[recipient] < claimVersion {
				continue
			}
		} else if m.allowlist != nil && !m.allowlist.allows(identity) {
			continue
		}
		if containsHome(homes, identity) {
			namedConnected = true
		}
		ready = append(ready, peerSendTarget{peer: peer.Peer, identityPK: peer.IdentityPK, identity: identity})
	}
	m.mu.RUnlock()
	if !namedConnected || claimVersion == 0 {
		return ready
	}
	selected := ready[:0]
	for _, target := range ready {
		if containsHome(homes, target.identity) {
			selected = append(selected, target)
		}
	}
	return selected
}
