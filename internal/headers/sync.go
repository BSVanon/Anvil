package headers

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/p2p"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

const (
	maxHeadersPerMsg = 2000
	syncRetryDelay   = 5 * time.Second
)

// HeaderPeer abstracts the peer interface for header sync, enabling mock peers in tests.
type HeaderPeer interface {
	RequestHeaders(locators []*chainhash.Hash, hashStop *chainhash.Hash) error
	ReadHeaders() ([]*wire.BlockHeader, error)
	Close() error
}

// Syncer synchronizes block headers from a Bitcoin P2P peer into the store.
type Syncer struct {
	store   *Store
	network wire.BitcoinNet
	logger  *slog.Logger

	mu    sync.RWMutex
	stats SyncStats
}

// SyncStats is a snapshot of the most recent header sync attempt.
type SyncStats struct {
	LastSource    string `json:"last_source,omitempty"`
	LastAttemptAt string `json:"last_attempt_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	LastTip       uint32 `json:"last_tip,omitempty"`
}

// NewSyncer creates a header syncer.
func NewSyncer(store *Store, network wire.BitcoinNet, logger *slog.Logger) *Syncer {
	return &Syncer{
		store:   store,
		network: network,
		logger:  logger,
	}
}

// SyncFrom connects to the given address and syncs headers to the chain tip.
// Returns the final height reached.
func (s *Syncer) SyncFrom(address string) (uint32, error) {
	s.recordAttempt(address)
	peer, err := p2p.Connect(address, s.network, s.logger)
	if err != nil {
		s.recordFailure(address, err)
		return 0, err
	}
	defer peer.Close()

	tip, err := s.SyncWith(peer)
	if err != nil {
		s.recordFailure(address, err)
		return 0, err
	}
	s.recordSuccess(address, tip)
	return tip, nil
}

// SyncWith syncs headers using the given peer (useful for testing with mock peers).
func (s *Syncer) SyncWith(peer HeaderPeer) (uint32, error) {
	startHeight := s.store.Tip()
	s.logger.Info("starting header sync", "from_height", startHeight)

	for {
		locators, err := s.buildLocator()
		if err != nil {
			return 0, fmt.Errorf("build locator: %w", err)
		}

		if err := peer.RequestHeaders(locators, nil); err != nil {
			return 0, fmt.Errorf("request headers: %w", err)
		}

		headers, err := peer.ReadHeaders()
		if err != nil {
			return 0, fmt.Errorf("read headers: %w", err)
		}

		if len(headers) == 0 {
			break
		}

		height := s.store.Tip() + 1
		if err := s.store.AddHeaders(height, headers); err != nil {
			return 0, fmt.Errorf("store headers at %d: %w", height, err)
		}

		newTip := s.store.Tip()
		s.logger.Info("synced headers",
			"count", len(headers),
			"tip", newTip,
		)

		if len(headers) < maxHeadersPerMsg {
			break
		}
	}

	finalTip := s.store.Tip()
	s.logger.Info("header sync complete",
		"height", finalTip,
		"synced", finalTip-startHeight,
	)
	return finalTip, nil
}

func (s *Syncer) Stats() SyncStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

func (s *Syncer) recordAttempt(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.LastSource = source
	s.stats.LastAttemptAt = time.Now().UTC().Format(time.RFC3339)
	s.stats.LastError = ""
}

func (s *Syncer) recordSuccess(source string, tip uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	s.stats.LastSource = source
	s.stats.LastAttemptAt = now
	s.stats.LastSuccessAt = now
	s.stats.LastError = ""
	s.stats.LastTip = tip
}

func (s *Syncer) recordFailure(source string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.LastSource = source
	s.stats.LastAttemptAt = time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		s.stats.LastError = err.Error()
	}
}

// buildLocator creates a block locator hash list from the current chain.
// Uses exponential step-back: first 10 hashes, then doubling steps.
// Always includes genesis as the final entry.
func (s *Syncer) buildLocator() ([]*chainhash.Hash, error) {
	tip := s.store.Tip()
	var locators []*chainhash.Hash
	step := uint32(1)
	height := tip
	addedGenesis := false

	for i := 0; i < 32; i++ {
		hash, err := s.store.HashAtHeight(height)
		if err != nil {
			return nil, fmt.Errorf("hash at %d: %w", height, err)
		}
		locators = append(locators, hash)

		if height == 0 {
			addedGenesis = true
			break
		}

		if i >= 10 {
			step *= 2
		}
		if height <= step {
			height = 0 // next iteration adds genesis
		} else {
			height -= step
		}
	}

	if !addedGenesis {
		genesis, err := s.store.HashAtHeight(0)
		if err != nil {
			return nil, fmt.Errorf("genesis hash: %w", err)
		}
		locators = append(locators, genesis)
	}

	return locators, nil
}
