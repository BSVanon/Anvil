package gossip

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"golang.org/x/net/websocket"

	"github.com/BSVanon/Anvil/internal/bond"
	"github.com/BSVanon/Anvil/internal/envelope"
)

// Manager wraps go-sdk auth.Peer instances for mesh communication.
// Each connected mesh peer is an authenticated session via auth.Peer.
// The auth layer handles identity verification and transport;
// this manager handles message routing and topic-scoped forwarding.
//
// This is the Go port of relay-federation's data-relay.js, using
// canonical go-sdk auth.Peer instead of bespoke WebSocket handshake.
type Manager struct {
	mu     sync.RWMutex
	wallet wallet.Interface
	store  *envelope.Store
	logger *slog.Logger

	// peers maps identity pubkey hex -> connected peer
	peers map[string]*MeshPeer

	// interests maps peer pubkey hex -> topic prefixes they declared
	interests map[string][]string

	// our topic interest prefixes (announced to peers on connect)
	localInterests []string

	// dedup: envelope hashes we've already seen
	seen    map[string]struct{}
	seenMu  sync.Mutex
	maxSeen int

	// callback for new envelopes from the mesh
	onEnvelope func(*envelope.Envelope)

	// overlay directory for SHIP gossip (nil = SHIP sync disabled)
	overlayDir OverlayDirectory

	// bond checker (nil = no bond required)
	bondChecker *bond.Checker
}

// OverlayDirectory is the interface for SHIP registration storage.
// Satisfied by overlay.Directory. Uses callback pattern to avoid
// shared type definitions across packages.
type OverlayDirectory interface {
	// ForEachSHIP calls fn for every SHIP registration. Stop iteration by returning false.
	ForEachSHIP(fn func(identity, domain, nodeName, topic string) bool)
	// AddSHIPPeerFromGossip stores a SHIP peer received from a trusted mesh peer.
	AddSHIPPeerFromGossip(identity, domain, nodeName, topic string) error
}

// MeshPeer represents a single authenticated mesh connection.
type MeshPeer struct {
	Peer       *auth.Peer
	IdentityPK *ec.PublicKey
	Endpoint   string
	origKey    string          // the original map key at insertion time (for cleanup after re-key)
	closeFunc  func() error   // closes the underlying transport connection
}

// ManagerConfig holds configuration for the gossip manager.
type ManagerConfig struct {
	Wallet         wallet.Interface
	Store          *envelope.Store
	Logger         *slog.Logger
	LocalInterests []string
	MaxSeen        int
	OnEnvelope     func(*envelope.Envelope)
	OverlayDir     OverlayDirectory
	BondChecker    *bond.Checker
}

// NewManager creates a gossip manager backed by go-sdk auth.Peer.
func NewManager(cfg ManagerConfig) *Manager {
	maxSeen := cfg.MaxSeen
	if maxSeen <= 0 {
		maxSeen = 10000
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		wallet:         cfg.Wallet,
		store:          cfg.Store,
		logger:         logger,
		peers:          make(map[string]*MeshPeer),
		interests:      make(map[string][]string),
		localInterests: cfg.LocalInterests,
		seen:           make(map[string]struct{}),
		maxSeen:        maxSeen,
		onEnvelope:     cfg.OnEnvelope,
		overlayDir:     cfg.OverlayDir,
		bondChecker:    cfg.BondChecker,
	}
}

// ConnectPeer establishes an authenticated mesh connection to a remote peer.
// Uses go-sdk auth.Peer + WebSocketTransport for BRC-31 identity verification.
// Requires a wallet — returns an error if none was configured.
func (m *Manager) ConnectPeer(ctx context.Context, endpoint string) error {
	if m.wallet == nil {
		return fmt.Errorf("cannot connect to peer: no wallet configured (identity.wif required)")
	}
	transport, err := NewWSTransportAdapter(endpoint)
	if err != nil {
		return fmt.Errorf("websocket transport: %w", err)
	}

	peer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    m.wallet,
		Transport: transport,
	})

	// Register message handler before starting
	peer.ListenForGeneralMessages(func(ctx context.Context, senderPK *ec.PublicKey, payload []byte) error {
		pkHex := fmt.Sprintf("%x", senderPK.Compressed())

		// Update peer identity on first message (auth handshake completes)
		m.mu.Lock()
		needsBondCheck := false
		if mp, ok := m.peers[endpoint]; ok && mp.IdentityPK == nil {
			mp.IdentityPK = senderPK
			m.peers[pkHex] = mp
			delete(m.peers, endpoint)
			needsBondCheck = true
		}
		m.mu.Unlock()

		// Verify bond on first message (identity just revealed)
		if needsBondCheck && m.bondChecker != nil && m.bondChecker.Required() {
			balance, err := m.bondChecker.VerifyBond(senderPK)
			if err != nil {
				m.logger.Warn("outbound peer rejected: insufficient bond",
					"peer", truncate(pkHex),
					"endpoint", endpoint,
					"error", err.Error())
				m.removePeer(pkHex)
				return fmt.Errorf("bond required: %w", err)
			}
			m.logger.Info("outbound peer bond verified",
				"peer", truncate(pkHex),
				"bond_sats", balance)
		}

		return m.handleMessage(pkHex, senderPK, payload)
	})

	if err := peer.Start(); err != nil {
		return fmt.Errorf("peer start: %w", err)
	}

	m.mu.Lock()
	m.peers[endpoint] = &MeshPeer{
		Peer:      peer,
		Endpoint:  endpoint,
		origKey:   endpoint,
		closeFunc: transport.Close,
	}
	m.mu.Unlock()

	m.logger.Info("mesh peer connecting", "endpoint", endpoint)

	// Start the read loop for incoming messages
	go transport.StartReceive()

	// Announce our topic interests
	if err := m.announceInterests(peer); err != nil {
		return err
	}

	// Share our SHIP registrations
	m.announceSHIP(peer)
	return nil
}


// BroadcastEnvelope sends an envelope to all interested peers.
// Called by the API layer when a new envelope is submitted via HTTP.
func (m *Manager) BroadcastEnvelope(env *envelope.Envelope) {
	// Respect no_gossip flag — local-only envelopes stay on this node
	if env.NoGossip {
		return
	}

	hash := envelope.HashEnvelope(env.Topic, env.Pubkey, env.Payload, env.Timestamp)
	m.seenMu.Lock()
	m.seen[hash] = struct{}{}
	m.seenMu.Unlock()

	raw, err := env.Marshal()
	if err != nil {
		return
	}
	m.forwardToInterested("", env.Topic, raw)
}

// AcceptPeer registers an inbound peer using a server-side transport.
// Called by the mesh listener for each accepted WebSocket connection.
// Returns the peer key used in the peers map and the transport's done channel.
func (m *Manager) AcceptPeer(transport *ServerWSTransport) (peerKey string, err error) {
	peer := auth.NewPeer(&auth.PeerOptions{
		Wallet:    m.wallet,
		Transport: transport,
	})

	// Use a temporary key until the auth handshake reveals the real identity
	tempKey := fmt.Sprintf("inbound-%p", transport)

	peer.ListenForGeneralMessages(func(ctx context.Context, senderPK *ec.PublicKey, payload []byte) error {
		pkHex := fmt.Sprintf("%x", senderPK.Compressed())

		m.mu.Lock()
		needsBondCheck := false
		if mp, ok := m.peers[tempKey]; ok && mp.IdentityPK == nil {
			mp.IdentityPK = senderPK
			m.peers[pkHex] = mp
			delete(m.peers, tempKey)
			needsBondCheck = true
		}
		m.mu.Unlock()

		// Verify bond on first message (identity just revealed)
		if needsBondCheck && m.bondChecker != nil && m.bondChecker.Required() {
			balance, err := m.bondChecker.VerifyBond(senderPK)
			if err != nil {
				m.logger.Warn("peer rejected: insufficient bond",
					"peer", truncate(pkHex),
					"error", err.Error())
				m.removePeer(pkHex)
				return fmt.Errorf("bond required: %w", err)
			}
			m.logger.Info("peer bond verified",
				"peer", truncate(pkHex),
				"bond_sats", balance)
		}

		return m.handleMessage(pkHex, senderPK, payload)
	})

	if err := peer.Start(); err != nil {
		return "", fmt.Errorf("peer start: %w", err)
	}

	m.mu.Lock()
	m.peers[tempKey] = &MeshPeer{
		Peer:      peer,
		Endpoint:  "inbound",
		origKey:   tempKey,
		closeFunc: transport.Close,
	}
	m.mu.Unlock()

	m.logger.Info("mesh peer accepted (inbound)")

	// Start the read loop in a goroutine; when it exits the done channel closes
	go transport.StartReceive()

	if err := m.announceInterests(peer); err != nil {
		return tempKey, err
	}
	m.announceSHIP(peer)
	return tempKey, nil
}

// removePeer removes a peer from the peers and interests maps.
// Pass the original key that was returned by AcceptPeer or used in ConnectPeer.
// After re-keying (temp key → identity pubkey), the peer's origKey field
// identifies it unambiguously even with multiple inbound peers.
func (m *Manager) removePeer(origKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Fast path: key hasn't been re-keyed yet
	if p, ok := m.peers[origKey]; ok {
		p.Peer.Stop()
		if p.closeFunc != nil {
			p.closeFunc()
		}
		delete(m.peers, origKey)
		delete(m.interests, origKey)
		return
	}

	// Slow path: peer was re-keyed to its identity pubkey.
	// Find it by matching origKey on the MeshPeer struct.
	for k, p := range m.peers {
		if p.origKey == origKey {
			p.Peer.Stop()
			if p.closeFunc != nil {
				p.closeFunc()
			}
			delete(m.peers, k)
			delete(m.interests, k)
			return
		}
	}
}

// MeshHandler returns an http.Handler that accepts inbound WebSocket
// connections for mesh peering. Mount this on the mesh listen address.
func (m *Manager) MeshHandler() http.Handler {
	return websocket.Handler(func(conn *websocket.Conn) {
		transport := NewServerWSTransport(conn)
		peerKey, err := m.AcceptPeer(transport)
		if err != nil {
			m.logger.Warn("inbound peer accept failed", "error", err)
			return
		}

		// Block until the connection closes, then clean up the peer.
		<-transport.Done()
		m.removePeer(peerKey)
		m.logger.Info("inbound peer disconnected, cleaned up", "key", truncate(peerKey))
	})
}

// PeerCount returns the number of connected mesh peers.
func (m *Manager) PeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

// PeerInfo holds public information about a connected mesh peer.
type PeerInfo struct {
	Identity string `json:"identity"`
	Endpoint string `json:"endpoint"`
}

// PeerList returns information about all connected mesh peers.
func (m *Manager) PeerList() []PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		info := PeerInfo{Endpoint: p.Endpoint}
		if p.IdentityPK != nil {
			info.Identity = fmt.Sprintf("%x", p.IdentityPK.Compressed())
		}
		list = append(list, info)
	}
	return list
}

// ConnectSeedWithReconnect connects to a seed peer and automatically
// reconnects if the connection drops. Blocks until ctx is cancelled.
// Designed to run in a goroutine per seed peer.
func (m *Manager) ConnectSeedWithReconnect(ctx context.Context, endpoint string, interval time.Duration) {
	for {
		transport, err := NewWSTransportAdapter(endpoint)
		if err != nil {
			m.logger.Warn("seed peer connect failed, retrying",
				"endpoint", endpoint, "error", err, "retry_in", interval)
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				continue
			}
		}

		peer := auth.NewPeer(&auth.PeerOptions{
			Wallet:    m.wallet,
			Transport: transport,
		})

		peer.ListenForGeneralMessages(func(ctx context.Context, senderPK *ec.PublicKey, payload []byte) error {
			pkHex := fmt.Sprintf("%x", senderPK.Compressed())

			m.mu.Lock()
			needsBondCheck := false
			if mp, ok := m.peers[endpoint]; ok && mp.IdentityPK == nil {
				mp.IdentityPK = senderPK
				m.peers[pkHex] = mp
				delete(m.peers, endpoint)
				needsBondCheck = true
			}
			m.mu.Unlock()

			if needsBondCheck && m.bondChecker != nil && m.bondChecker.Required() {
				balance, err := m.bondChecker.VerifyBond(senderPK)
				if err != nil {
					m.logger.Warn("outbound peer rejected: insufficient bond",
						"peer", truncate(pkHex),
						"endpoint", endpoint,
						"error", err.Error())
					m.removePeer(pkHex)
					return fmt.Errorf("bond required: %w", err)
				}
				m.logger.Info("outbound peer bond verified",
					"peer", truncate(pkHex),
					"bond_sats", balance)
			}

			return m.handleMessage(pkHex, senderPK, payload)
		})

		if err := peer.Start(); err != nil {
			m.logger.Warn("seed peer start failed, retrying",
				"endpoint", endpoint, "error", err, "retry_in", interval)
			transport.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				continue
			}
		}

		m.mu.Lock()
		m.peers[endpoint] = &MeshPeer{
			Peer:      peer,
			Endpoint:  endpoint,
			origKey:   endpoint,
			closeFunc: transport.Close,
		}
		m.mu.Unlock()

		m.logger.Info("seed peer connected", "endpoint", endpoint)

		go transport.StartReceive()

		if err := m.announceInterests(peer); err != nil {
			m.logger.Warn("seed peer interest announce failed", "endpoint", endpoint, "error", err)
		}
		m.announceSHIP(peer)

		// Wait for connection to drop or context cancel
		select {
		case <-transport.Done():
			m.removePeer(endpoint)
			m.logger.Warn("seed peer disconnected, reconnecting",
				"endpoint", endpoint, "retry_in", interval)
		case <-ctx.Done():
			m.removePeer(endpoint)
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// Stop gracefully disconnects all peers, closing their transport connections.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, peer := range m.peers {
		if peer.Peer != nil {
			peer.Peer.Stop()
		}
		if peer.closeFunc != nil {
			peer.closeFunc()
		}
	}
	m.peers = make(map[string]*MeshPeer)
}

func truncate(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}
