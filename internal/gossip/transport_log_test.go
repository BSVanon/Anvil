package gossip

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestTransportWarningLimiterBounded(t *testing.T) {
	limiter := transportWarningLimiter{}
	now := time.Now()
	for i := 0; i < transportCloseWarnEntries*3; i++ {
		if !limiter.allow(fmt.Sprintf("peer-%d", i), now) {
			t.Fatalf("new warning key %d was suppressed", i)
		}
		limiter.mu.Lock()
		entries := len(limiter.at)
		limiter.mu.Unlock()
		if entries > transportCloseWarnEntries {
			t.Fatalf("warning limiter grew to %d entries, max %d", entries, transportCloseWarnEntries)
		}
	}
}

func TestNodeQueueFullCloseIsWarningCounted(t *testing.T) {
	manager := NewManager(ManagerConfig{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	manager.warnTransportClose(&MeshPeer{Endpoint: "peer.example"}, transportCloseNodeQueueFull)
	manager.transports.warnings.mu.Lock()
	_, counted := manager.transports.warnings.at["peer.example"]
	manager.transports.warnings.mu.Unlock()
	if !counted {
		t.Fatal("node_queue_full close was not recorded by the warning limiter")
	}
}
