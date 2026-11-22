package gossip

import (
	"context"
	"fmt"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// AcceptPeer registers an inbound peer using a server-side transport.
// Called by the mesh listener for each accepted WebSocket connection.
// Returns the peer key used in the peers map and the transport's done channel.
func (m *Manager) AcceptPeer(transport *ServerWSTransport) (peerKey string, err error) {
	m.attachTransport(transport)
	peer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    m.wallet,
		Transport: transport,
	})

	connKey, connectionID := m.nextConnection("inbound")
	connectedAt := time.Now()
	mp := &MeshPeer{
		Peer:         peer,
		Endpoint:     transport.RemoteAddr(),
		Direction:    "inbound",
		ConnectedAt:  connectedAt,
		origKey:      connKey,
		connectionID: connectionID,
		closeFunc:    transport.Close,
		transport:    transport,
	}
	transport.setOnFrame(func() { mp.lastFrameAt.Store(time.Now().UnixNano()) })
	peer.ListenForGeneralMessages(func(ctx context.Context, senderPK *ec.PublicKey, payload []byte) error {
		return m.handlePeerMessage(ctx, mp, transport, senderPK, payload)
	})

	if err := peer.Start(); err != nil {
		_ = transport.Close()
		return "", fmt.Errorf("peer start: %w", err)
	}

	m.mu.Lock()
	mp.lastFrameAt.Store(time.Now().UnixNano())
	m.peers[connKey] = mp
	peerCount := len(m.peers)
	m.mu.Unlock()

	m.logger.Info("mesh peer accepted (inbound)")
	m.recordConnectionEvent(ConnectionEvent{
		Direction: "inbound",
		Event:     "connected",
		Endpoint:  transport.RemoteAddr(),
		PeerCount: peerCount,
	})
	m.logLiveDataReady(peerCount)

	// Start the read loop in a goroutine; when it exits the done channel closes
	go transport.StartReceive()

	// No unconditional announce here: AcceptPeer can't gate the handshake
	// itself (BRC-31 is mutual — we only learn the dialer's identity by
	// completing it), so the earliest point this side can check
	// allowed_peers is reactively, inside the ListenForGeneralMessages
	// callback above, once the dialer sends its own first message. That
	// callback replies with our announces only after that check passes.
	return connKey, nil
}
