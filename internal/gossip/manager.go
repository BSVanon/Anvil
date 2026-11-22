package gossip

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/BSVanon/Anvil/internal/bond"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/messaging"
)

const maxCatchUpRounds = 5 // max pagination rounds per topic on reconnect

func cfgRatePerSec(v float64) float64 {
	if v > 0 {
		return v
	}
	return 30 // default: 30 envelopes/second per peer
}

func cfgRateBurst(v int) int {
	if v > 0 {
		return v
	}
	return 100 // default: burst 100
}

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
	msgSeen map[string]struct{}
	seenMu  sync.Mutex
	maxSeen int
	// seenOwners maps a msgSeen entry to the in-flight forward that set it (guarded by seenMu).
	seenOwners map[string]*forwardSeenOwner

	// callback for new envelopes from the mesh
	onEnvelope func(*envelope.Envelope)

	// overlay directory for SHIP gossip (nil = SHIP sync disabled)
	overlayDir        OverlayDirectory
	shipForwardWindow time.Duration
	shipForwardMu     sync.Mutex
	shipForwarded     map[string]time.Time

	// bond checker (nil = no bond required)
	bondChecker *bond.Checker

	// allowlist enforces [mesh] allowed_peers (nil/empty set = no
	// restriction, today's behaviour)
	allowlist *peerAllowlist

	// per-peer gossip rate limiting (loose defaults: 30/s burst 100)
	peerRates  map[string]*peerRate
	peerRateMu sync.Mutex
	homeRates  map[string]*homeControlRate
	homeRateMu sync.Mutex

	// unstoredRelay budgets relays of forwards this node could not store.
	unstoredRelay unstoredRelayBucket
	ratePerSec    float64
	rateBurst     int

	// slash tracking
	slashTracker *slashTracker

	// topics to request catch-up for on peer connect
	catchUpTopics []string
	catchUpRounds map[string]int // tracks pagination rounds per "peer:topic" key

	// local pubkeys used for SHIP re-announce filtering
	localPubkeys map[string]struct{}
	connLog      *ConnectionLog

	// TX relay
	txMempool    Mempool      // nil = TX relay disabled
	onTxCallback OnTxCallback // called when new tx received via mesh

	// Point-to-point messaging (BRC-33)
	msgStore    *messaging.Store // nil = messaging forwarding disabled
	identityKey *ec.PrivateKey   // node identity key for signing messages

	// onACMEChallengeHook receives a decoded MsgACMEChallenge (the
	// gateway's replicated ACME challenge cache). nil (gateway mode off,
	// or not wired up yet) means the message is decoded then dropped — see
	// acme_relay.go.
	onACMEChallengeHook func(senderPKHex, key string, value []byte, expires time.Time)
	// messagingPolicy holds the Home Rule, forward_copy_ttl
	// and forward_peers configuration (handlers_msg_policy.go). The zero
	// value reproduces today's behaviour exactly.
	messagingPolicy MessagingPolicy

	// Demand tracking: topic → subscriber/query count (local node).
	// Updated by SSE hub and query handlers. Gossiped in heartbeat.
	demandMu  sync.RWMutex
	demandMap map[string]int

	// activity counters (lock-free atomics — safe to increment under RLock)
	envsReceived atomic.Int64
	envsSent     atomic.Int64
	shipReceived atomic.Int64
	startedAt    time.Time

	// mesh health counters for GET /stats (lock-free atomics, cumulative
	// since boot — see status.go). dedupEvictions covers both seen and
	// msgSeen; duplicateArrivals covers every "already seen" discard
	// (envelope, message forward, slash warning); catchupTruncated counts
	// catch-up sequences cut off at maxCatchUpRounds while more remained.
	dedupEvictions    atomic.Int64
	duplicateArrivals atomic.Int64
	catchupTruncated  atomic.Int64
	sendDropped       atomic.Int64

	// unauthConns counts inbound MeshHandler connections currently open
	// that have not yet reached MarkAuthorized (see reserveUnauthConn).
	unauthConns atomic.Int32

	// Every socket gets a process-unique key. Endpoints are not unique: two
	// configured URLs can resolve to the same node, and reciprocal seed dials
	// deliberately create two sockets until duplicate resolution runs.
	connSeq       atomic.Uint64
	localIdentity string
	pex           *peerExchangeState
	transports    managerTransportState

	// Duplicate convergence is enabled per remote identity only after that
	// peer advertises exact-connection removal support. Keeping this state
	// scoped to the current live connections makes rolling upgrades safe even
	// if a node later rolls back while retaining its identity key.
	duplicateSafePeers map[string]struct{}
	identityRemovalSeq map[string]uint64
	// disableDuplicateConvergence emulates a peer predating capability
	// negotiation in real-transport compatibility coverage.
	disableDuplicateConvergence bool
}

// peerRate tracks token-bucket rate limiting for a single peer.
type peerRate struct {
	tokens     float64
	lastSeen   time.Time
	dropCount  int       // drops since last warn
	lastWarnAt time.Time // last spam warning sent
}

// OverlayDirectory is the interface for SHIP registration storage.
// Satisfied by overlay.Directory. Uses callback pattern to avoid
// shared type definitions across packages.
type OverlayDirectory interface {
	// ForEachSHIP calls fn for every SHIP registration. Stop iteration by returning false.
	ForEachSHIP(fn func(identity, domain, nodeName, version, topic string) bool)
	// AddSHIPPeerFromGossip stores a SHIP peer received from a trusted mesh peer.
	AddSHIPPeerFromGossip(identity, domain, nodeName, version, topic string) error
	// RemoveSHIPPeerByIdentity removes all SHIP registrations for a given identity.
	RemoveSHIPPeerByIdentity(identity string)
}

// MeshPeer represents a single authenticated mesh connection.
type MeshPeer struct {
	Peer         *auth.Peer
	IdentityPK   *ec.PublicKey
	Endpoint     string
	Direction    string
	BondSats     int          // verified bond amount in satoshis (0 = not checked)
	Version      string       // remote node version (from SHIP sync)
	ConnectedAt  time.Time    // when this peer connected
	origKey      string       // process-unique connection key (stable across identity re-keying)
	connectionID uint64       // process-unique creation sequence for identity-removal barriers
	closeFunc    func() error // closes the underlying transport connection
	transport    *ServerWSTransport
	exchange     bool         // opened by the peer-exchange dial loop
	seed         bool         // opened from a configured [mesh] seeds entry
	lastFrameAt  atomic.Int64 // Unix nanoseconds; updated by the receive loop

	// bondChecked and admitted are guarded by Manager.mu. admitted is the
	// application gate: identity binding, duplicate selection, allowlist, and
	// bond verification have all succeeded for this exact socket.
	bondChecked        bool
	admitted           bool
	closed             bool
	closeReason        string
	privateHomeVersion int
	appliedHomeClaims  map[string]int64
	admissionMu        sync.Mutex
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
	// AllowedPeers restricts mesh peering ([mesh] allowed_peers) to these
	// identity public key hexes, inbound and outbound. Empty means no
	// restriction — today's behaviour.
	AllowedPeers []string
	// CatchUpTopics are topics to request from peers on connect.
	// Ensures new nodes receive critical data (catalog, feeds) immediately.
	CatchUpTopics []string
	// LocalPubkeys are identity pubkey hexes for this node's apps.
	LocalPubkeys  []string
	ConnectionLog *ConnectionLog
	// IdentityKey is the node's private key for signing messages.
	IdentityKey *ec.PrivateKey
	// RatePerSec is the per-peer envelope rate limit (default: 30).
	RatePerSec float64
	// RateBurst is the per-peer burst allowance (default: 100).
	RateBurst int
	// TxMempool enables mesh TX relay. When set, the manager announces
	// txids to peers and responds to tx requests from the local mempool.
	TxMempool Mempool
	// OnTx is called when a new transaction is received via the mesh.
	OnTx OnTxCallback
	// PeerExchange enables heartbeat peer records and exchange dialing.
	PeerExchange bool
	// MaxExchangePeers caps live connections opened by peer exchange.
	MaxExchangePeers int
	// SeedURLs are excluded from exchange dialing and never count toward its cap.
	SeedURLs []string
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
	m := &Manager{
		wallet:             cfg.Wallet,
		store:              cfg.Store,
		logger:             logger,
		peers:              make(map[string]*MeshPeer),
		interests:          make(map[string][]string),
		localInterests:     cfg.LocalInterests,
		seen:               make(map[string]struct{}),
		msgSeen:            make(map[string]struct{}),
		maxSeen:            maxSeen,
		onEnvelope:         cfg.OnEnvelope,
		overlayDir:         cfg.OverlayDir,
		shipForwardWindow:  defaultSHIPForwardWindow,
		shipForwarded:      make(map[string]time.Time),
		bondChecker:        cfg.BondChecker,
		allowlist:          newPeerAllowlist(cfg.AllowedPeers),
		peerRates:          make(map[string]*peerRate),
		homeRates:          make(map[string]*homeControlRate),
		ratePerSec:         cfgRatePerSec(cfg.RatePerSec),
		rateBurst:          cfgRateBurst(cfg.RateBurst),
		slashTracker:       newSlashTracker(),
		localPubkeys:       make(map[string]struct{}),
		connLog:            cfg.ConnectionLog,
		txMempool:          cfg.TxMempool,
		onTxCallback:       cfg.OnTx,
		duplicateSafePeers: make(map[string]struct{}),
		identityRemovalSeq: make(map[string]uint64),
	}
	m.startedAt = time.Now()
	m.catchUpTopics = cfg.CatchUpTopics
	m.catchUpRounds = make(map[string]int)
	m.identityKey = cfg.IdentityKey
	if cfg.IdentityKey != nil {
		m.localIdentity = fmt.Sprintf("%x", cfg.IdentityKey.PubKey().Compressed())
	} else if cfg.Wallet != nil {
		identityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if result, err := cfg.Wallet.GetPublicKey(identityCtx, wallet.GetPublicKeyArgs{IdentityKey: true}, ""); err == nil && result != nil && result.PublicKey != nil {
			m.localIdentity = fmt.Sprintf("%x", result.PublicKey.Compressed())
		}
	}
	m.pex = newPeerExchangeState(cfg.PeerExchange, cfg.MaxExchangePeers, cfg.SeedURLs)
	for _, pk := range cfg.LocalPubkeys {
		pk = strings.ToLower(strings.TrimSpace(pk))
		if pk == "" {
			continue
		}
		m.localPubkeys[pk] = struct{}{}
	}
	return m
}

// ConnectPeer establishes an authenticated mesh connection to a remote peer.
// Uses go-sdk auth.Peer + WebSocketTransport for BRC-31 identity verification.
// Requires a wallet — returns an error if none was configured.
func (m *Manager) ConnectPeer(ctx context.Context, endpoint string) error {
	_, _, _, err := m.connectPeer(ctx, endpoint, connectPeerOptions{})
	return err
}

// BroadcastEnvelope sends an envelope to all interested peers.
// Called by the API layer when a new envelope is submitted via HTTP.
func (m *Manager) BroadcastEnvelope(env *envelope.Envelope) {
	// Respect no_gossip / private flags — neither is pushed to peers.
	// (private additionally blocks the pull + unauthenticated read paths.)
	if env.NoGossip || env.Private {
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
