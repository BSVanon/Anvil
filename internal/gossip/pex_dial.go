package gossip

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

var (
	peerExchangeDialInterval = 30 * time.Second
	peerExchangeBackoffBase  = time.Minute
	peerExchangeBackoffMax   = time.Hour
	peerExchangeMismatchWait = 6 * time.Hour
)

// RunPeerExchange maintains bounded connections learned from authenticated
// heartbeat advertisements. Configured seeds are excluded from this loop.
func (m *Manager) RunPeerExchange(ctx context.Context) {
	if m.pex == nil || !m.pex.enabled || m.pex.maxPeers == 0 {
		return
	}
	ticker := time.NewTicker(peerExchangeDialInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, candidate := range m.exchangeCandidates(now) {
				go m.dialExchangeCandidate(ctx, candidate)
			}
		}
	}
}

func (m *Manager) exchangeCandidates(now time.Time) []*peerCandidate {
	connected := make(map[string]struct{})
	liveExchange := 0
	m.mu.RLock()
	for identity, peer := range m.peers {
		if peer.admitted && peer.IdentityPK != nil {
			connected[peerIdentity(peer)] = struct{}{}
		}
		if peer.exchange && admittedPrimaryLocked(identity, peer) {
			liveExchange++
		}
	}
	m.mu.RUnlock()

	m.pex.mu.Lock()
	defer m.pex.mu.Unlock()
	inFlight := 0
	for _, candidate := range m.pex.candidates {
		if candidate.Dialing {
			inFlight++
		}
	}
	available := m.pex.maxPeers - liveExchange - inFlight
	if available <= 0 {
		return nil
	}
	eligible := make([]*peerCandidate, 0, len(m.pex.candidates))
	for _, candidate := range m.pex.candidates {
		if candidate.Dialing || !freshPeerAdvert(candidate.AdvertisedAt, now) || now.Before(candidate.NextTry) {
			continue
		}
		if candidate.Identity == m.localIdentity || !m.allowlist.allows(candidate.Identity) {
			continue
		}
		if _, ok := connected[candidate.Identity]; ok {
			continue
		}
		if _, seed := m.pex.seedURLs[candidate.URL]; seed {
			continue
		}
		if _, configuredSeed := m.pex.seedIDs[candidate.Identity]; configuredSeed {
			continue
		}
		eligible = append(eligible, candidate)
	}
	rand.Shuffle(len(eligible), func(i, j int) { eligible[i], eligible[j] = eligible[j], eligible[i] })
	limit := min(2, available, len(eligible))
	selected := make([]*peerCandidate, 0, limit)
	for _, candidate := range eligible[:limit] {
		candidate.Dialing = true
		copyCandidate := *candidate
		selected = append(selected, &copyCandidate)
	}
	return selected
}

func (m *Manager) dialExchangeCandidate(ctx context.Context, candidate *peerCandidate) {
	closedMode := m.allowlist != nil && m.allowlist.enabled()
	mp, transport, _, err := m.connectPeer(ctx, candidate.URL, connectPeerOptions{
		expectedIdentity: candidate.Identity,
		exchange:         true,
		guardPrivate:     !closedMode,
		dialTimeout:      10 * time.Second,
	})
	if err != nil {
		m.noteExchangeFailure(candidate.Identity, errors.Is(err, errIdentityMismatch))
		return
	}
	m.noteExchangeSuccess(candidate.Identity)
	select {
	case <-ctx.Done():
		m.removeMeshPeerWithReason(mp, "context_cancelled")
	case <-transport.Done():
		reason := transport.CloseReason()
		if reason == "" {
			reason = "transport_closed"
		}
		m.removeMeshPeerWithReason(mp, reason)
	}
	m.pex.mu.Lock()
	if current := m.pex.candidates[candidate.Identity]; current != nil {
		current.Dialing = false
		current.NextTry = time.Now().Add(peerExchangeBackoffBase)
	}
	m.pex.mu.Unlock()
}

func (m *Manager) noteExchangeSuccess(identity string) {
	m.pex.mu.Lock()
	if candidate := m.pex.candidates[identity]; candidate != nil {
		candidate.Dialing = false
		candidate.Failures = 0
		candidate.NextTry = time.Time{}
	}
	m.pex.mu.Unlock()
}

func (m *Manager) noteExchangeFailure(identity string, mismatch bool) {
	now := time.Now()
	m.pex.mu.Lock()
	defer m.pex.mu.Unlock()
	candidate := m.pex.candidates[identity]
	if candidate == nil {
		return
	}
	candidate.Dialing = false
	if mismatch {
		candidate.NextTry = now.Add(peerExchangeMismatchWait)
		return
	}
	candidate.Failures++
	delay := peerExchangeBackoffBase * time.Duration(uint64(1)<<min(candidate.Failures-1, 10))
	if delay > peerExchangeBackoffMax {
		delay = peerExchangeBackoffMax
	}
	candidate.NextTry = now.Add(delay)
}
