package gossip

import (
	"context"
	"sync"
	"time"
)

const (
	unstoredRelayRate  = 10.0
	unstoredRelayBurst = 50
)

type unstoredRelayBucket struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
	dropped    int
	lastWarn   time.Time
}

var relayForwardTestHook func(*Manager, string, MsgForwardPayload)

func relayBucketFor(m *Manager) *unstoredRelayBucket {
	return &m.unstoredRelay
}

func (m *Manager) allowUnstoredRelay() bool {
	bucket := relayBucketFor(m)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	now := time.Now()
	if bucket.lastRefill.IsZero() {
		bucket.tokens, bucket.lastRefill = unstoredRelayBurst, now
	}
	if elapsed := now.Sub(bucket.lastRefill).Seconds(); elapsed > 0 {
		bucket.tokens += elapsed * unstoredRelayRate
		if bucket.tokens > unstoredRelayBurst {
			bucket.tokens = unstoredRelayBurst
		}
		bucket.lastRefill = now
	}
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	bucket.dropped++
	if bucket.lastWarn.IsZero() || now.Sub(bucket.lastWarn) >= time.Minute {
		m.logger.Warn("forwarded message unstored relay budget exhausted", "dropped", bucket.dropped)
		bucket.dropped = 0
		bucket.lastWarn = now
	}
	return false
}

func (m *Manager) relayMessageForward(senderPKHex string, fwd MsgForwardPayload) {
	if relayForwardTestHook != nil {
		relayForwardTestHook(m, senderPKHex, fwd)
		return
	}
	payload, err := Encode(MsgForward, fwd)
	if err != nil {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for pkHex, peer := range m.peers {
		if pkHex != senderPKHex && peer.Peer != nil {
			_ = peer.Peer.ToPeer(context.Background(), payload, peer.IdentityPK, 5000)
		}
	}
}
