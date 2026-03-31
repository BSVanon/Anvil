package gossip

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ConnectionEvent is a persistent record of a mesh peer lifecycle transition.
type ConnectionEvent struct {
	Timestamp    string `json:"timestamp"`
	Direction    string `json:"direction,omitempty"`
	Event        string `json:"event"`
	Endpoint     string `json:"endpoint,omitempty"`
	Identity     string `json:"identity,omitempty"`
	BondSats     int    `json:"bond_sats,omitempty"`
	PeerCount    int    `json:"peer_count,omitempty"`
	ConnectedAt  string `json:"connected_at,omitempty"`
	DurationSecs int    `json:"duration_secs,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// ConnectionLog appends peer lifecycle events to a durable JSONL file and
// keeps a small in-memory tail for status endpoints.
type ConnectionLog struct {
	path      string
	maxRecent int

	mu     sync.Mutex
	recent []ConnectionEvent
}

func NewConnectionLog(path string, maxRecent int) (*ConnectionLog, error) {
	if maxRecent <= 0 {
		maxRecent = 50
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	return &ConnectionLog{path: path, maxRecent: maxRecent}, nil
}

func (l *ConnectionLog) Record(event ConnectionEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	line, err := json.Marshal(event)
	if err == nil {
		if f, openErr := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); openErr == nil {
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}
	}

	l.recent = append(l.recent, event)
	if len(l.recent) > l.maxRecent {
		l.recent = append([]ConnectionEvent(nil), l.recent[len(l.recent)-l.maxRecent:]...)
	}
}

func (l *ConnectionLog) Recent(limit int) []ConnectionEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > len(l.recent) {
		limit = len(l.recent)
	}
	if limit == 0 {
		return nil
	}
	start := len(l.recent) - limit
	out := make([]ConnectionEvent, limit)
	copy(out, l.recent[start:])
	return out
}

func (m *Manager) recordConnectionEvent(event ConnectionEvent) {
	if m.connLog == nil || event.Event == "" {
		return
	}
	m.connLog.Record(event)
}

func (m *Manager) RecentConnections(limit int) []ConnectionEvent {
	if m.connLog == nil {
		return nil
	}
	return m.connLog.Recent(limit)
}

func (m *Manager) notePeerIdentity(identity string) {
	m.mu.RLock()
	peer, ok := m.peers[identity]
	peerCount := len(m.peers)
	m.mu.RUnlock()
	if !ok {
		return
	}
	m.recordConnectionEvent(ConnectionEvent{
		Direction:   peer.Direction,
		Event:       "identified",
		Endpoint:    peer.Endpoint,
		Identity:    identity,
		BondSats:    peer.BondSats,
		PeerCount:   peerCount,
		ConnectedAt: peer.ConnectedAt.UTC().Format(time.RFC3339),
	})
	m.logLiveDataReady(peerCount)
}

func (m *Manager) disconnectEventForPeer(peer *MeshPeer, reason string, peerCount int) ConnectionEvent {
	event := ConnectionEvent{
		Direction: peer.Direction,
		Event:     "disconnected",
		Endpoint:  peer.Endpoint,
		PeerCount: peerCount,
		Reason:    reason,
	}
	if peer.IdentityPK != nil {
		event.Identity = fmt.Sprintf("%x", peer.IdentityPK.Compressed())
	}
	if !peer.ConnectedAt.IsZero() {
		event.ConnectedAt = peer.ConnectedAt.UTC().Format(time.RFC3339)
		event.DurationSecs = int(time.Since(peer.ConnectedAt).Seconds())
	}
	if peer.BondSats > 0 {
		event.BondSats = peer.BondSats
	}
	return event
}

func (m *Manager) logLiveDataReady(peerCount int) {
	if peerCount <= 0 {
		return
	}
	m.logger.Info("receiving live data from peers", "connected_peers", peerCount)
}
