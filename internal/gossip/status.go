package gossip

// Status and metrics exports for the gossip manager.
// Split from manager.go for file size discipline.

import (
	"fmt"
	"time"
)

// PeerInfo holds public information about a connected mesh peer.
type PeerInfo struct {
	Identity    string `json:"identity"`
	Endpoint    string `json:"endpoint"`
	BondSats    int    `json:"bond_sats,omitempty"`
	Version     string `json:"version,omitempty"`
	ConnectedAt string `json:"connected_at,omitempty"`
	UptimeSecs  int    `json:"uptime_secs,omitempty"`
}

// PeerList returns information about all connected mesh peers.
func (m *Manager) PeerList() []PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	list := make([]PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		info := PeerInfo{Endpoint: p.Endpoint, BondSats: p.BondSats, Version: p.Version}
		if p.IdentityPK != nil {
			info.Identity = fmt.Sprintf("%x", p.IdentityPK.Compressed())
		}
		if !p.ConnectedAt.IsZero() {
			info.ConnectedAt = p.ConnectedAt.UTC().Format(time.RFC3339)
			info.UptimeSecs = int(now.Sub(p.ConnectedAt).Seconds())
		}
		list = append(list, info)
	}
	return list
}

// ActivityStats holds mesh-level counters for the status endpoint.
type ActivityStats struct {
	EnvsReceived int64  `json:"envelopes_received"`
	EnvsSent     int64  `json:"envelopes_sent"`
	StartedAt    string `json:"started_at"`
	UptimeSecs   int    `json:"uptime_secs"`
}

// Activity returns mesh activity counters.
func (m *Manager) Activity() ActivityStats {
	return ActivityStats{
		EnvsReceived: m.envsReceived.Load(),
		EnvsSent:     m.envsSent.Load(),
		StartedAt:    m.startedAt.UTC().Format(time.RFC3339),
		UptimeSecs:   int(time.Since(m.startedAt).Seconds()),
	}
}

// IncrReceived bumps the received envelope counter (lock-free).
func (m *Manager) IncrReceived() { m.envsReceived.Add(1) }

// IncrSent bumps the sent envelope counter (lock-free).
func (m *Manager) IncrSent() { m.envsSent.Add(1) }

// Interests returns declared topic interests for all connected peers.
func (m *Manager) Interests() map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]string, len(m.interests))
	for k, v := range m.interests {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}
