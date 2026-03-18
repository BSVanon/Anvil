package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"golang.org/x/net/websocket"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// Manager wraps go-sdk auth.Peer instances for mesh communication.
// Each connected forge peer is an authenticated session via auth.Peer.
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
		if mp, ok := m.peers[endpoint]; ok && mp.IdentityPK == nil {
			mp.IdentityPK = senderPK
			// Re-key from endpoint to pubkey
			m.peers[pkHex] = mp
			delete(m.peers, endpoint)
		}
		m.mu.Unlock()

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
	return m.announceInterests(peer)
}

// announceInterests sends our topic declarations to a peer.
func (m *Manager) announceInterests(peer *auth.Peer) error {
	payload, err := Encode(MsgTopics, TopicsPayload{Prefixes: m.localInterests})
	if err != nil {
		return err
	}
	ctx := context.Background()
	return peer.ToPeer(ctx, payload, nil, 5000)
}

// handleMessage processes an incoming mesh message from an authenticated peer.
func (m *Manager) handleMessage(senderPKHex string, senderPK *ec.PublicKey, payload []byte) error {
	msg, err := Decode(payload)
	if err != nil {
		m.logger.Warn("invalid mesh message", "error", err)
		return nil // don't break the connection for bad messages
	}

	switch msg.Type {
	case MsgData:
		return m.onData(senderPKHex, msg.Data)
	case MsgTopics:
		return m.onTopics(senderPKHex, msg.Data)
	case MsgDataRequest:
		return m.onDataRequest(senderPKHex, senderPK, msg.Data)
	case MsgDataResponse:
		return m.onDataResponse(msg.Data)
	default:
		m.logger.Debug("unknown mesh message type", "type", msg.Type)
	}
	return nil
}

// onData handles an incoming data envelope from a peer.
func (m *Manager) onData(senderPK string, raw json.RawMessage) error {
	env, err := envelope.UnmarshalEnvelope(raw)
	if err != nil {
		return nil
	}

	// Dedup check
	hash := envelope.HashEnvelope(env.Topic, env.Pubkey, env.Timestamp)
	m.seenMu.Lock()
	if _, seen := m.seen[hash]; seen {
		m.seenMu.Unlock()
		return nil
	}
	if len(m.seen) >= m.maxSeen {
		// FIFO eviction: clear half
		count := 0
		for k := range m.seen {
			delete(m.seen, k)
			count++
			if count >= m.maxSeen/2 {
				break
			}
		}
	}
	m.seen[hash] = struct{}{}
	m.seenMu.Unlock()

	// Validate signature
	if err := env.Validate(); err != nil {
		m.logger.Debug("envelope signature invalid", "topic", env.Topic, "error", err)
		return nil
	}

	// Store
	if m.store != nil {
		if err := m.store.Ingest(env); err != nil {
			m.logger.Warn("envelope store error", "error", err)
		}
	}

	// Notify callback
	if m.onEnvelope != nil {
		m.onEnvelope(env)
	}

	// Forward to interested peers (except sender)
	m.forwardToInterested(senderPK, env.Topic, raw)

	return nil
}

// onTopics handles a peer's interest declaration.
func (m *Manager) onTopics(senderPK string, raw json.RawMessage) error {
	var tp TopicsPayload
	if err := json.Unmarshal(raw, &tp); err != nil {
		return nil
	}
	m.mu.Lock()
	m.interests[senderPK] = tp.Prefixes
	m.mu.Unlock()
	m.logger.Debug("peer interests updated", "peer", truncate(senderPK), "prefixes", tp.Prefixes)
	return nil
}

// onDataRequest handles a pull-based catch-up query. Responds without re-gossiping.
func (m *Manager) onDataRequest(senderPKHex string, senderPK *ec.PublicKey, raw json.RawMessage) error {
	var req DataRequestPayload
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil
	}

	if m.store == nil {
		return nil
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	results, _ := m.store.QueryByTopic(req.Topic, limit)

	resp, err := Encode(MsgDataResponse, DataResponsePayload{
		Topic:     req.Topic,
		Envelopes: results,
		HasMore:   false,
	})
	if err != nil {
		return err
	}

	// Send directly to requester — no gossip
	m.mu.RLock()
	peer, ok := m.peers[senderPKHex]
	m.mu.RUnlock()
	if ok && peer.Peer != nil {
		return peer.Peer.ToPeer(context.Background(), resp, senderPK, 5000)
	}
	return nil
}

// onDataResponse handles catch-up response. Stores locally without re-gossiping.
func (m *Manager) onDataResponse(raw json.RawMessage) error {
	var resp DataResponsePayload
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil
	}

	for _, env := range resp.Envelopes {
		if err := env.Validate(); err != nil {
			continue
		}
		if m.store != nil {
			m.store.Ingest(env)
		}
	}
	return nil
}

// forwardToInterested sends an envelope to peers whose declared interests match the topic.
func (m *Manager) forwardToInterested(senderPK string, topic string, rawEnvelope json.RawMessage) {
	encoded, err := Encode(MsgData, rawEnvelope)
	if err != nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for pkHex, peer := range m.peers {
		if pkHex == senderPK {
			continue // don't echo back to sender
		}

		prefixes := m.interests[pkHex]
		for _, prefix := range prefixes {
			if strings.HasPrefix(topic, prefix) {
				if peer.Peer != nil {
					peer.Peer.ToPeer(context.Background(), encoded, peer.IdentityPK, 5000)
				}
				break
			}
		}
	}
}

// BroadcastEnvelope sends an envelope to all interested peers.
// Called by the API layer when a new envelope is submitted via HTTP.
func (m *Manager) BroadcastEnvelope(env *envelope.Envelope) {
	hash := envelope.HashEnvelope(env.Topic, env.Pubkey, env.Timestamp)
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
		if mp, ok := m.peers[tempKey]; ok && mp.IdentityPK == nil {
			mp.IdentityPK = senderPK
			m.peers[pkHex] = mp
			delete(m.peers, tempKey)
		}
		m.mu.Unlock()

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
