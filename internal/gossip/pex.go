package gossip

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
)

const maxPeerExchangeCandidates = 1000

type peerCandidate struct {
	Identity     string
	URL          string
	AdvertisedAt time.Time
	NextTry      time.Time
	Failures     int
	Dialing      bool
}

type peerExchangeState struct {
	mu sync.Mutex

	enabled     bool
	maxPeers    int
	seedURLs    map[string]struct{}
	seedIDs     map[string]struct{}
	candidates  map[string]*peerCandidate
	advertURL   string
	advertState string
}

func newPeerExchangeState(enabled bool, maxPeers int, seeds []string) *peerExchangeState {
	p := &peerExchangeState{
		enabled: enabled, maxPeers: maxPeers, seedURLs: make(map[string]struct{}, len(seeds)),
		seedIDs:    make(map[string]struct{}, len(seeds)),
		candidates: make(map[string]*peerCandidate), advertState: "off",
	}
	if enabled {
		p.advertState = "none"
	}
	for _, seed := range seeds {
		p.seedURLs[seed] = struct{}{}
	}
	return p
}

func (m *Manager) noteSeedIdentity(identity string) {
	if m.pex == nil || identity == "" {
		return
	}
	m.pex.mu.Lock()
	m.pex.seedIDs[identity] = struct{}{}
	m.pex.mu.Unlock()
}

// validateAdvertiseURL applies the wire-record bound as well as its URL shape
// rules. DNS and address safety are checked later against the actual dial.
func validateAdvertiseURL(raw string) error {
	if len(raw) == 0 || len(raw) > 512 {
		return fmt.Errorf("must be between 1 and 512 bytes")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("scheme must be ws:// or wss://")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("host is required")
	}
	if u.User != nil {
		return fmt.Errorf("userinfo is not allowed")
	}
	if u.RawQuery != "" {
		return fmt.Errorf("query is not allowed")
	}
	if u.Fragment != "" {
		return fmt.Errorf("fragment is not allowed")
	}
	return nil
}

// observePeerAdvert is called only after the envelope signature validates.
// Its local payload shape intentionally avoids a dependency on internal/feeds.
func (m *Manager) observePeerAdvert(env *envelope.Envelope) {
	if m.pex == nil || !m.pex.enabled || env.Topic != "mesh:heartbeat" {
		return
	}
	var heartbeat struct {
		MeshURL string `json:"mesh_url"`
	}
	if json.Unmarshal([]byte(env.Payload), &heartbeat) != nil || heartbeat.MeshURL == "" {
		return
	}
	identity := strings.ToLower(env.Pubkey)
	if identity == "" || identity == m.localIdentity || validateAdvertiseURL(heartbeat.MeshURL) != nil {
		return
	}
	advertisedAt := time.Unix(env.Timestamp, 0)
	if !freshPeerAdvert(advertisedAt, time.Now()) {
		return
	}

	m.pex.mu.Lock()
	defer m.pex.mu.Unlock()
	if prior := m.pex.candidates[identity]; prior != nil {
		if !advertisedAt.After(prior.AdvertisedAt) {
			return
		}
		prior.URL = heartbeat.MeshURL
		prior.AdvertisedAt = advertisedAt
		return
	}
	if len(m.pex.candidates) >= maxPeerExchangeCandidates {
		var oldestIdentity string
		var oldest time.Time
		for candidateIdentity, candidate := range m.pex.candidates {
			if oldestIdentity == "" || candidate.AdvertisedAt.Before(oldest) {
				oldestIdentity, oldest = candidateIdentity, candidate.AdvertisedAt
			}
		}
		delete(m.pex.candidates, oldestIdentity)
	}
	m.pex.candidates[identity] = &peerCandidate{
		Identity: identity, URL: heartbeat.MeshURL, AdvertisedAt: advertisedAt,
	}
}

func freshPeerAdvert(advertisedAt, now time.Time) bool {
	return !advertisedAt.Before(now.Add(-time.Hour)) && !advertisedAt.After(now.Add(10*time.Minute))
}

type PeerExchangeStatus struct {
	Enabled        bool   `json:"enabled"`
	AdvertisedURL  string `json:"advertised_url"`
	AdvertiseState string `json:"advertise_state"`
	Candidates     int    `json:"candidates"`
	ExchangePeers  int    `json:"exchange_peers"`
}

func (m *Manager) PeerExchangeStatus() PeerExchangeStatus {
	status := PeerExchangeStatus{}
	if m.pex == nil {
		status.AdvertiseState = "off"
		return status
	}
	m.pex.mu.Lock()
	status.Enabled = m.pex.enabled
	status.AdvertisedURL = m.pex.advertURL
	status.AdvertiseState = m.pex.advertState
	status.Candidates = len(m.pex.candidates)
	m.pex.mu.Unlock()
	m.mu.RLock()
	for identity, peer := range m.peers {
		if peer.exchange && admittedPrimaryLocked(identity, peer) {
			status.ExchangePeers++
		}
	}
	m.mu.RUnlock()
	return status
}

func (m *Manager) PeerExchangeAdvertisedURL() string {
	if m.pex == nil {
		return ""
	}
	m.pex.mu.Lock()
	defer m.pex.mu.Unlock()
	return m.pex.advertURL
}
