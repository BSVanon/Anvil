package gossip

import (
	"sync"
	"time"
)

const (
	transportCloseWarnInterval = time.Minute
	transportCloseWarnEntries  = 4096
)

type transportWarningLimiter struct {
	mu sync.Mutex
	at map[string]time.Time
}

func (m *Manager) warnTransportClose(peer *MeshPeer, reason string) {
	if reason != transportCloseQueueFull && reason != transportCloseNodeQueueFull &&
		reason != transportCloseTimeout && reason != transportCloseWriteError {
		return
	}
	key := peerIdentity(peer)
	if key == "" {
		key = peer.Endpoint
	}
	now := time.Now()
	if !m.transports.warnings.allow(key, now) {
		return
	}
	m.logger.Warn("mesh transport closed", "peer", truncate(key), "reason", reason)
}

func (l *transportWarningLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if last := l.at[key]; now.Sub(last) < transportCloseWarnInterval {
		return false
	}
	if _, exists := l.at[key]; !exists && len(l.at) >= transportCloseWarnEntries {
		for existing, at := range l.at {
			if now.Sub(at) > transportCloseWarnInterval {
				delete(l.at, existing)
			}
		}
		if len(l.at) >= transportCloseWarnEntries {
			clear(l.at)
		}
	}
	if l.at == nil {
		l.at = make(map[string]time.Time)
	}
	l.at[key] = now
	return true
}
