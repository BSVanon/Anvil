package feeds

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

func testPublisher(t *testing.T) (*Publisher, *envelope.Store, []*envelope.Envelope) {
	t.Helper()
	key, _ := ec.NewPrivateKey()
	dir, _ := os.MkdirTemp("", "anvil-feeds-*")
	t.Cleanup(func() { os.RemoveAll(dir) })
	store, err := envelope.NewStore(dir, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	var broadcast []*envelope.Envelope
	pub := NewPublisher(key, store, func(env *envelope.Envelope) {
		broadcast = append(broadcast, env)
	}, "test-node", "0.5.0", slog.Default())

	return pub, store, broadcast
}

func TestHeartbeatPublish(t *testing.T) {
	pub, store, _ := testPublisher(t)

	ctx, cancel := context.WithCancel(context.Background())

	// Run heartbeat for one tick
	go pub.RunHeartbeat(ctx, 50*time.Millisecond, HeartbeatSources{
		HeightFn: func() uint32 { return 100 },
		PeersFn:  func() int { return 2 },
		TopicsFn: func() map[string]int { return map[string]int{"test:topic": 5} },
		DemandFn: func() map[string]int { return map[string]int{"test:topic": 3} },
	})

	// Wait for at least 2 heartbeats
	time.Sleep(150 * time.Millisecond)
	cancel()

	envs, err := store.QueryByTopic("mesh:heartbeat", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) == 0 {
		t.Fatal("no heartbeat envelopes published")
	}

	var hb HeartbeatPayload
	if err := json.Unmarshal([]byte(envs[0].Payload), &hb); err != nil {
		t.Fatalf("invalid heartbeat payload: %v", err)
	}
	if hb.Node != "test-node" {
		t.Errorf("expected node=test-node, got %q", hb.Node)
	}
	if hb.Height != 100 {
		t.Errorf("expected height=100, got %d", hb.Height)
	}
	if hb.Peers != 2 {
		t.Errorf("expected peers=2, got %d", hb.Peers)
	}
}

// TestHeartbeatIncludesUpstreamStatus verifies the new upstream_status field
// is populated when an UpstreamFn callback is provided. Wallet consumers use
// this field for federation-node failover decisions.
func TestHeartbeatIncludesUpstreamStatus(t *testing.T) {
	pub, store, _ := testPublisher(t)

	ctx, cancel := context.WithCancel(context.Background())

	go pub.RunHeartbeat(ctx, 50*time.Millisecond, HeartbeatSources{
		HeightFn: func() uint32 { return 100 },
		PeersFn:  func() int { return 2 },
		TopicsFn: func() map[string]int { return map[string]int{"t": 1} },
		UpstreamFn: func() *UpstreamStatus {
			return &UpstreamStatus{
				Broadcast:          "healthy",
				HeadersSyncLagSecs: 42,
			}
		},
	})

	time.Sleep(120 * time.Millisecond)
	cancel()

	envs, _ := store.QueryByTopic("mesh:heartbeat", 10)
	if len(envs) == 0 {
		t.Fatal("no heartbeat envelopes published")
	}

	var hb HeartbeatPayload
	if err := json.Unmarshal([]byte(envs[0].Payload), &hb); err != nil {
		t.Fatalf("invalid heartbeat payload: %v", err)
	}
	if hb.UpstreamStatus == nil {
		t.Fatal("expected upstream_status to be populated")
	}
	if hb.UpstreamStatus.Broadcast != "healthy" {
		t.Errorf("expected broadcast=healthy, got %q", hb.UpstreamStatus.Broadcast)
	}
	if hb.UpstreamStatus.HeadersSyncLagSecs != 42 {
		t.Errorf("expected headers_sync_lag_secs=42, got %d", hb.UpstreamStatus.HeadersSyncLagSecs)
	}
}

// TestHeartbeatOmitsUpstreamStatusWhenNotProvided verifies the field is
// omitted (JSON omitempty) when the caller doesn't supply an UpstreamFn.
// Protects backward compatibility for older Anvil consumers.
func TestHeartbeatOmitsUpstreamStatusWhenNotProvided(t *testing.T) {
	pub, store, _ := testPublisher(t)
	ctx, cancel := context.WithCancel(context.Background())

	go pub.RunHeartbeat(ctx, 50*time.Millisecond, HeartbeatSources{
		HeightFn: func() uint32 { return 1 },
		PeersFn:  func() int { return 0 },
		TopicsFn: func() map[string]int { return nil },
	})

	time.Sleep(120 * time.Millisecond)
	cancel()

	envs, _ := store.QueryByTopic("mesh:heartbeat", 10)
	if len(envs) == 0 {
		t.Fatal("no heartbeat envelopes published")
	}

	// Parse as a generic map so we can check field presence explicitly
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(envs[0].Payload), &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["upstream_status"]; present {
		t.Error("upstream_status should be omitted when UpstreamFn not provided")
	}
}

func TestBlockTipPublish(t *testing.T) {
	pub, store, _ := testPublisher(t)

	var height atomic.Uint32
	height.Store(100)
	ctx, cancel := context.WithCancel(context.Background())

	go pub.RunBlockTip(ctx, 50*time.Millisecond,
		func() uint32 { return height.Load() },
		func(h uint32) string { return "00000000abcdef1234567890abcdef1234567890abcdef1234567890abcdef12" },
	)

	// Wait, then advance height
	time.Sleep(80 * time.Millisecond)
	height.Store(101)
	time.Sleep(80 * time.Millisecond)
	cancel()

	envs, err := store.QueryByTopic("mesh:blocks", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) == 0 {
		t.Fatal("no block tip envelopes published")
	}

	var tip BlockTipPayload
	if err := json.Unmarshal([]byte(envs[0].Payload), &tip); err != nil {
		t.Fatalf("invalid block tip payload: %v", err)
	}
	if tip.Height != 101 {
		t.Errorf("expected height=101, got %d", tip.Height)
	}
}

func TestBlockTipSkipsEmptyHash(t *testing.T) {
	pub, store, _ := testPublisher(t)

	var height atomic.Uint32
	height.Store(100)
	ctx, cancel := context.WithCancel(context.Background())

	go pub.RunBlockTip(ctx, 50*time.Millisecond,
		func() uint32 { return height.Load() },
		func(h uint32) string { return "" }, // simulate hash lookup failure
	)

	time.Sleep(80 * time.Millisecond)
	height.Store(101)
	time.Sleep(80 * time.Millisecond)
	cancel()

	envs, _ := store.QueryByTopic("mesh:blocks", 10)
	if len(envs) != 0 {
		t.Errorf("expected 0 block envelopes when hash is empty, got %d", len(envs))
	}
}

func TestTruncateHash(t *testing.T) {
	if got := truncateHash("abcdef1234567890extra"); got != "abcdef1234567890" {
		t.Errorf("expected truncation, got %q", got)
	}
	if got := truncateHash("short"); got != "short" {
		t.Errorf("expected no truncation, got %q", got)
	}
	if got := truncateHash(""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}
