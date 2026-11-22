package gossip

import (
	"context"

	"github.com/bsv-blockchain/go-sdk/auth"
)

// requestCatchUp asks a peer for recent envelopes on topics this node cares about.
func (m *Manager) requestCatchUp(peer *auth.Peer) {
	seen := make(map[string]struct{})
	var topics []string
	for _, topic := range m.catchUpTopics {
		if _, ok := seen[topic]; !ok {
			seen[topic] = struct{}{}
			topics = append(topics, topic)
		}
	}
	for _, prefix := range m.localInterests {
		if prefix == "" {
			continue
		}
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			topics = append(topics, prefix)
		}
	}
	for _, topic := range topics {
		payload, err := Encode(MsgDataRequest, DataRequestPayload{Topic: topic, Limit: 50})
		if err == nil {
			_ = peer.ToPeer(context.Background(), payload, nil, 5000)
		}
	}
	if len(topics) > 0 {
		m.logger.Debug("catch-up requested", "topics", topics)
	}
}

// announceInterests sends our topic declarations and connection capabilities.
func (m *Manager) announceInterests(peer *auth.Peer) error {
	topics := TopicsPayload{Prefixes: m.localInterests}
	if !m.disableDuplicateConvergence {
		topics.Capabilities = []string{exactRemovalCapability}
	}
	payload, err := Encode(MsgTopics, topics)
	if err != nil {
		return err
	}
	if err := peer.ToPeer(context.Background(), payload, nil, 5000); err != nil {
		return err
	}
	go m.announcePrivateHomes(peer)
	return nil
}

// announceSHIP sends all local SHIP registrations to one admitted peer.
func (m *Manager) announceSHIP(peer *auth.Peer) {
	if m.overlayDir == nil {
		return
	}
	var peers []SHIPPeerInfo
	m.overlayDir.ForEachSHIP(func(identity, domain, nodeName, version, topic string) bool {
		peers = append(peers, SHIPPeerInfo{
			IdentityPub: identity, Domain: domain, NodeName: nodeName, Version: version, Topic: topic,
		})
		return true
	})
	if len(peers) == 0 {
		return
	}
	payload, err := Encode(MsgSHIPSync, SHIPSyncPayload{Peers: peers})
	if err == nil {
		_ = peer.ToPeer(context.Background(), payload, nil, 5000)
	}
}

// ReannounceToAll sends this node's own SHIP registrations to admitted peers.
func (m *Manager) ReannounceToAll() {
	m.ResyncPrivateHomes()
	if m.overlayDir == nil {
		return
	}
	var peers []SHIPPeerInfo
	m.overlayDir.ForEachSHIP(func(identity, domain, nodeName, version, topic string) bool {
		if _, isLocal := m.localPubkeys[identity]; isLocal {
			peers = append(peers, SHIPPeerInfo{
				IdentityPub: identity, Domain: domain, NodeName: nodeName, Version: version, Topic: topic,
			})
		}
		return true
	})
	if len(peers) == 0 {
		return
	}
	payload, err := Encode(MsgSHIPSync, SHIPSyncPayload{Peers: peers})
	if err != nil {
		return
	}
	for _, peer := range m.admittedPeers("") {
		_ = peer.peer.ToPeer(context.Background(), payload, peer.identityPK, 5000)
	}
}
