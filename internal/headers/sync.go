package headers

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/BSVanon/Anvil/internal/p2p"
	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

const (
	maxHeadersPerMsg = 2000
	syncRetryDelay   = 5 * time.Second
)

// Syncer synchronizes block headers from a Bitcoin P2P peer into the store.
type Syncer struct {
	store   *Store
	network wire.BitcoinNet
	logger  *slog.Logger
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
	peer, err := p2p.Connect(address, s.network, s.logger)
	if err != nil {
		return 0, err
	}
	defer peer.Close()

	startHeight := s.store.Tip()
	s.logger.Info("starting header sync", "from_height", startHeight, "peer", address)

	for {
		// Build block locator from current tip
		locators, err := s.buildLocator()
		if err != nil {
			return 0, fmt.Errorf("build locator: %w", err)
		}

		// Request headers
		if err := peer.RequestHeaders(locators, nil); err != nil {
			return 0, fmt.Errorf("request headers: %w", err)
		}

		// Read response
		headers, err := peer.ReadHeaders()
		if err != nil {
			return 0, fmt.Errorf("read headers: %w", err)
		}

		if len(headers) == 0 {
			// Caught up to tip
			break
		}

		// Store headers
		height := s.store.Tip() + 1
		if err := s.store.AddHeaders(height, headers); err != nil {
			return 0, fmt.Errorf("store headers at %d: %w", height, err)
		}

		newTip := s.store.Tip()
		s.logger.Info("synced headers",
			"count", len(headers),
			"tip", newTip,
		)

		// If we got fewer than max, we're at the tip
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

// buildLocator creates a block locator hash list from the current chain.
// Uses exponential step-back: first 10 hashes, then doubling steps.
func (s *Syncer) buildLocator() ([]*chainhash.Hash, error) {
	tip := s.store.Tip()
	var locators []*chainhash.Hash
	step := uint32(1)
	height := tip

	for i := 0; i < 32 && height > 0; i++ {
		hash, err := s.store.HashAtHeight(height)
		if err != nil {
			return nil, fmt.Errorf("hash at %d: %w", height, err)
		}
		locators = append(locators, hash)

		if i >= 10 {
			step *= 2
		}
		if height < step {
			height = 0
		} else {
			height -= step
		}
	}

	// Always include genesis
	if height != 0 || len(locators) == 0 {
		genesis, err := s.store.HashAtHeight(0)
		if err != nil {
			return nil, fmt.Errorf("genesis hash: %w", err)
		}
		locators = append(locators, genesis)
	}

	return locators, nil
}
