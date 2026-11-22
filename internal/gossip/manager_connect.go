package gossip

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type connectPeerOptions struct {
	expectedIdentity string
	exchange         bool
	seed             bool
	guardPrivate     bool
	dialTimeout      time.Duration
}

// connectPeer is the single outbound connection path. expectedIdentity is
// empty for configured seeds and mandatory for learned peer records.
func (m *Manager) connectPeer(ctx context.Context, endpoint string, opts connectPeerOptions) (*MeshPeer, *ServerWSTransport, string, error) {
	if m.wallet == nil {
		return nil, nil, "", fmt.Errorf("cannot connect to peer: no wallet configured (identity.wif required)")
	}
	transport, err := newWSTransportAdapter(endpoint, opts.dialTimeout, opts.guardPrivate)
	if err != nil {
		return nil, nil, "", fmt.Errorf("websocket transport: %w", err)
	}
	m.attachTransport(transport)
	peer := auth.NewPeer(&auth.PeerOptions{Wallet: m.wallet, Transport: transport})
	connKey, connectionID := m.nextConnection("outbound")
	connectedAt := time.Now()
	mp := &MeshPeer{
		Peer:         peer,
		Endpoint:     endpoint,
		Direction:    "outbound",
		ConnectedAt:  connectedAt,
		origKey:      connKey,
		connectionID: connectionID,
		closeFunc:    transport.Close,
		transport:    transport,
		exchange:     opts.exchange,
		seed:         opts.seed,
	}
	transport.setOnFrame(func() { mp.lastFrameAt.Store(time.Now().UnixNano()) })
	peer.ListenForGeneralMessages(func(callbackCtx context.Context, senderPK *ec.PublicKey, payload []byte) error {
		return m.handlePeerMessage(callbackCtx, mp, transport, senderPK, payload)
	})
	if err := peer.Start(); err != nil {
		_ = transport.Close()
		return nil, nil, "", fmt.Errorf("peer start: %w", err)
	}

	m.mu.Lock()
	mp.lastFrameAt.Store(time.Now().UnixNano())
	m.peers[mp.origKey] = mp
	peerCount := len(m.peers)
	m.mu.Unlock()
	m.recordConnectionEvent(ConnectionEvent{
		Direction: "outbound", Event: "connected", Endpoint: endpoint, PeerCount: peerCount,
	})
	m.logLiveDataReady(peerCount)
	go transport.StartReceive()

	identity, err := m.establishAndAuthorizePeer(ctx, peer, mp, strings.ToLower(opts.expectedIdentity), endpoint, 10000)
	if err != nil {
		if !errors.Is(err, errDuplicateConnection) && !errors.Is(err, errSelfConnection) && !errors.Is(err, errPeerRefused) && !errors.Is(err, errIdentityMismatch) && !errors.Is(err, errBondRejected) && !errors.Is(err, errIdentityRemoved) && !errors.Is(err, errConnectionClosed) {
			m.removeMeshPeerWithReason(mp, "handshake_failed")
		}
		return mp, transport, identity, fmt.Errorf("peer identity not established: %w", err)
	}
	if !m.hasPeerConnection(mp) {
		return mp, transport, identity, errDuplicateConnection
	}
	transport.MarkAuthorized()
	if err := m.announceInterests(peer); err != nil {
		if !m.hasPeerConnection(mp) {
			return mp, transport, identity, errDuplicateConnection
		}
		m.removeMeshPeerWithReason(mp, "interest_announce_failed")
		return mp, transport, identity, err
	}
	if !m.hasPeerConnection(mp) {
		return mp, transport, identity, errDuplicateConnection
	}
	m.announceSHIP(peer)
	if !m.hasPeerConnection(mp) {
		return mp, transport, identity, errDuplicateConnection
	}
	m.requestCatchUp(peer)
	return mp, transport, identity, nil
}

// handlePeerMessage gates the first general message for both directions. No
// application message is processed until identity, duplicate, allowlist, and
// bond decisions have completed for this exact socket.
func (m *Manager) handlePeerMessage(ctx context.Context, mp *MeshPeer, transport *ServerWSTransport, senderPK *ec.PublicKey, payload []byte) error {
	identity := fmt.Sprintf("%x", senderPK.Compressed())
	m.noteDuplicateCapability(identity, payload)
	mp.admissionMu.Lock()
	m.mu.RLock()
	current := m.peerMappedLocked(mp)
	needsAdmission := current && !mp.admitted
	m.mu.RUnlock()
	if !current {
		mp.admissionMu.Unlock()
		return errDuplicateConnection
	}
	if needsAdmission && !m.allowPeerExact(mp, identity, mp.Direction, mp.Endpoint) {
		mp.admissionMu.Unlock()
		return errPeerRefused
	}
	balance := 0
	if needsAdmission && m.bondChecker != nil && m.bondChecker.Required() {
		var verifyErr error
		balance, verifyErr = m.bondChecker.VerifyBond(senderPK)
		if verifyErr != nil {
			m.logger.Warn("peer rejected: insufficient bond", "peer", truncate(identity), "endpoint", mp.Endpoint, "error", verifyErr)
			m.removeMeshPeerWithReason(mp, "bond_rejected")
			mp.admissionMu.Unlock()
			return fmt.Errorf("bond required: %w", verifyErr)
		}
	}
	firstIdentity, err := m.bindPeerIdentity(mp, senderPK, true)
	if err != nil {
		mp.admissionMu.Unlock()
		return err
	}
	newlyAdmitted := needsAdmission && m.admitPeer(mp, balance)
	mp.admissionMu.Unlock()
	if needsAdmission && !newlyAdmitted {
		return errDuplicateConnection
	}
	if firstIdentity || newlyAdmitted {
		m.notePeerIdentity(identity)
	}
	if newlyAdmitted && mp.Direction == "inbound" {
		transport.MarkAuthorized()
		if announceErr := m.announceInterests(mp.Peer); announceErr != nil {
			m.logger.Warn("inbound peer interest announce failed", "peer", truncate(identity), "error", announceErr)
		}
		m.announceSHIP(mp.Peer)
		m.requestCatchUp(mp.Peer)
	}
	return m.handleMessage(identity, senderPK, payload)
}

func (m *Manager) allowPeerExact(mp *MeshPeer, identity, direction, endpoint string) bool {
	if m.allowlist == nil || m.allowlist.allows(identity) {
		return true
	}
	if m.allowlist.shouldLog(identity, time.Now()) {
		m.logger.Warn("peer identity refused: not in [mesh] allowed_peers",
			"peer", truncate(identity), "direction", direction, "endpoint", endpoint)
	}
	m.removeMeshPeerWithReason(mp, "not_allowed")
	return false
}
