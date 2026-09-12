package headers

import (
	"errors"
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
			// A prev-hash mismatch means our tip may sit on a minority fork:
			// the peer's headers build on a different block at/below our tip.
			// Attempt a most-work reorg rather than getting permanently stuck —
			// the exact failure that silently froze nodes for days.
			if errors.Is(err, ErrPrevHashMismatch) {
				adopted, forkHeight, rerr := s.store.ReorgTo(headers)
				if rerr != nil {
					return 0, fmt.Errorf("reorg from height %d: %w", height, rerr)
				}
				if !adopted {
					// Valid but not heavier — keep our chain, stop pulling this fork.
					s.logger.Warn("received lighter fork, keeping current chain",
						"fork_height", forkHeight, "tip", s.store.Tip())
					break
				}
				s.logger.Info("reorg adopted",
					"fork_height", forkHeight, "new_tip", s.store.Tip(), "count", len(headers))
				if len(headers) < maxHeadersPerMsg {
					break
				}
				continue
			}
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

// SyncFromHTTPPeer catches up (or reorgs) the header chain from a TRUSTED,
// operator-configured peer Anvil node's HTTP header API (config
// header_fallback_peers) — the fallback used when BSV P2P peers are unreachable
// or stale. Every fetched header is applied through the SAME PoW + linkage +
// most-work validation (AddHeaders / ReorgTo) as a native BSV peer: it rejects a
// lower-work chain and any header failing its own stated target, but does not
// verify difficulty-adjustment, so a configured peer is trusted to the same
// degree as a [bsv] node. Returns the resulting tip height (unchanged when the
// peer is not ahead — the caller then tries the next configured peer).
func (s *Syncer) SyncFromHTTPPeer(baseURL string) (uint32, error) {
	label := "mesh:" + baseURL

	src := NewHTTPHeaderSource(baseURL)
	peerTip, err := src.Tip()
	if err != nil {
		// Tip probe failed. Surface to the caller (which logs) but do NOT record a
		// sync attempt: this fallback is probed every poll, so a no-op or failed
		// probe must not overwrite the real (BSV P2P) source in /status stats.
		return 0, fmt.Errorf("peer tip: %w", err)
	}
	ourTip := s.store.Tip()
	if peerTip <= ourTip {
		// Peer not ahead — a no-op probe; leave sync stats untouched.
		return ourTip, nil
	}

	// Peer is genuinely ahead: a real sync from this source, worth recording.
	s.recordAttempt(label)
	ancestor, forked, err := s.findCommonAncestorHTTP(src, ourTip)
	if err != nil {
		s.recordFailure(label, err)
		return 0, err
	}

	if !forked {
		// Forward catch-up: our tip is a valid ancestor of the peer's chain.
		for from := ancestor + 1; from <= peerTip; from += httpMaxHeadersPerReq {
			count := peerTip - from + 1
			if count > httpMaxHeadersPerReq {
				count = httpMaxHeadersPerReq
			}
			hdrs, err := src.HeadersFrom(from, count)
			if err != nil {
				s.recordFailure(label, err)
				return 0, err
			}
			if len(hdrs) == 0 {
				break
			}
			if err := s.store.AddHeaders(s.store.Tip()+1, hdrs); err != nil {
				s.recordFailure(label, err)
				return 0, fmt.Errorf("apply headers at %d: %w", from, err)
			}
		}
	} else {
		// Fork: accumulate the whole competing branch (bounded) and let ReorgTo
		// apply the most-work rule. The bound (maxReorgDepth + a batch of
		// headroom) stops a hostile peer from making us buffer unbounded data.
		var branch []*wire.BlockHeader
		for from := ancestor + 1; from <= peerTip; from += httpMaxHeadersPerReq {
			count := peerTip - from + 1
			if count > httpMaxHeadersPerReq {
				count = httpMaxHeadersPerReq
			}
			hdrs, err := src.HeadersFrom(from, count)
			if err != nil {
				s.recordFailure(label, err)
				return 0, err
			}
			branch = append(branch, hdrs...)
			if len(branch) > maxReorgDepth+httpMaxHeadersPerReq {
				berr := fmt.Errorf("peer fork branch exceeds %d headers — leaving to BSV P2P", maxReorgDepth)
				s.recordFailure(label, berr)
				return 0, berr
			}
		}
		adopted, forkHeight, err := s.store.ReorgTo(branch)
		if err != nil {
			s.recordFailure(label, err)
			return 0, fmt.Errorf("reorg from peer: %w", err)
		}
		if !adopted {
			s.logger.Warn("mesh peer offered a lighter fork, keeping current chain",
				"fork_height", forkHeight, "tip", s.store.Tip())
		}
	}

	tip := s.store.Tip()
	s.recordSuccess(label, tip)
	s.logger.Info("mesh header sync complete", "peer", baseURL, "tip", tip)
	return tip, nil
}

// findCommonAncestorHTTP returns the highest height at which our chain and the
// peer's chain agree, walking back from ourTip up to maxReorgDepth. `forked` is
// false when the common ancestor IS our tip (a pure forward catch-up — the
// overwhelmingly common case, resolved in a single request).
func (s *Syncer) findCommonAncestorHTTP(src *HTTPHeaderSource, ourTip uint32) (ancestor uint32, forked bool, err error) {
	floor := uint32(0)
	if ourTip > maxReorgDepth {
		floor = ourTip - maxReorgDepth
	}
	for h := ourTip; ; h-- {
		ourHash, herr := s.store.HashAtHeight(h)
		if herr != nil {
			return 0, false, fmt.Errorf("local hash at %d: %w", h, herr)
		}
		peerHash, perr := src.HashAt(h)
		if perr != nil {
			return 0, false, fmt.Errorf("peer hash at %d: %w", h, perr)
		}
		if ourHash.IsEqual(peerHash) {
			return h, h != ourTip, nil
		}
		if h == floor {
			return 0, false, fmt.Errorf("no common ancestor within %d blocks of tip %d", maxReorgDepth, ourTip)
		}
	}
}

// SyncFromHTTPPeers tries each trusted fallback peer in order and returns as soon
// as one advances our tip. A not-ahead or erroring peer is skipped
// (non-terminal), so a stale first peer never blocks a healthy later one.
// Returns the resulting tip and whether any peer advanced us this call.
func (s *Syncer) SyncFromHTTPPeers(peers []string) (uint32, bool) {
	for _, p := range peers {
		pre := s.store.Tip()
		tip, err := s.SyncFromHTTPPeer(p)
		if err != nil {
			s.logger.Warn("header fallback peer failed", "peer", p, "error", err)
			continue
		}
		if tip > pre {
			s.logger.Info("header fallback sync", "peer", p, "from", pre, "to", tip)
			return tip, true
		}
	}
	return s.store.Tip(), false
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
