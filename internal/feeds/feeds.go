// Package feeds provides built-in data publishers that make mesh activity
// visible from the moment a node connects. These are infrastructure-level
// feeds (not app-layer), broadcasting node presence and chain state.
package feeds

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// Publisher publishes signed envelopes into the local store and gossip mesh.
type Publisher struct {
	key       *ec.PrivateKey
	store     *envelope.Store
	broadcast func(*envelope.Envelope)
	logger    *slog.Logger
	nodeName  string
	version   string
}

// NewPublisher creates a feed publisher backed by the node's identity key.
func NewPublisher(key *ec.PrivateKey, store *envelope.Store, broadcast func(*envelope.Envelope), nodeName, version string, logger *slog.Logger) *Publisher {
	return &Publisher{
		key:       key,
		store:     store,
		broadcast: broadcast,
		logger:    logger,
		nodeName:  nodeName,
		version:   version,
	}
}

// publish creates, signs, ingests, and broadcasts an envelope.
func (p *Publisher) publish(topic, payload string, ttl int) {
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     topic,
		Payload:   payload,
		TTL:       ttl,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(p.key)

	if err := p.store.Ingest(env); err != nil {
		p.logger.Warn("feed publish failed", "topic", topic, "error", err)
		return
	}
	if p.broadcast != nil {
		p.broadcast(env)
	}
}

// HeartbeatPayload is the JSON payload for mesh:heartbeat envelopes.
type HeartbeatPayload struct {
	Node      string         `json:"node"`
	Version   string         `json:"version"`
	Height    uint32         `json:"height"`
	Peers     int            `json:"peers"`
	Topics    []string       `json:"topics"`
	Demand    map[string]int `json:"demand,omitempty"` // topic → subscriber/query count
	Timestamp int64          `json:"ts"`
}

// RunHeartbeat publishes a mesh:heartbeat envelope every interval.
// The heartbeat announces this node's presence and basic stats so
// newly connected nodes immediately see live data flowing.
func (p *Publisher) RunHeartbeat(ctx context.Context, interval time.Duration, heightFn func() uint32, peerCountFn func() int, topicsFn func() map[string]int, demandFn func() map[string]int) {
	ttl := int(interval.Seconds()) * 5
	if ttl < 300 {
		ttl = 300
	}

	// Publish immediately on start, then on interval
	p.publishHeartbeat(ttl, heightFn, peerCountFn, topicsFn, demandFn)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.publishHeartbeat(ttl, heightFn, peerCountFn, topicsFn, demandFn)
		}
	}
}

func (p *Publisher) publishHeartbeat(ttl int, heightFn func() uint32, peerCountFn func() int, topicsFn func() map[string]int, demandFn func() map[string]int) {
	topicMap := topicsFn()
	topicNames := make([]string, 0, len(topicMap))
	for t := range topicMap {
		topicNames = append(topicNames, t)
	}

	var demand map[string]int
	if demandFn != nil {
		demand = demandFn()
	}

	hb := HeartbeatPayload{
		Node:      p.nodeName,
		Version:   p.version,
		Height:    heightFn(),
		Peers:     peerCountFn(),
		Topics:    topicNames,
		Demand:    demand,
		Timestamp: time.Now().Unix(),
	}
	data, _ := json.Marshal(hb)
	p.publish("mesh:heartbeat", string(data), ttl)
	p.logger.Debug("heartbeat published", "height", hb.Height, "peers", hb.Peers)
}

// BlockTipPayload is the JSON payload for mesh:blocks envelopes.
type BlockTipPayload struct {
	Height uint32 `json:"height"`
	Hash   string `json:"hash"`
	Node   string `json:"node"`
}

// RunBlockTip polls the header chain and publishes a mesh:blocks envelope
// whenever the tip advances. Each new block is visible to every mesh peer.
func (p *Publisher) RunBlockTip(ctx context.Context, pollInterval time.Duration, heightFn func() uint32, hashFn func(uint32) string) {
	lastHeight := heightFn()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h := heightFn()
			if h > lastHeight {
				hash := hashFn(h)
				if hash == "" {
					p.logger.Warn("block tip hash lookup failed, skipping", "height", h)
					continue
				}
				tip := BlockTipPayload{
					Height: h,
					Hash:   hash,
					Node:   p.nodeName,
				}
				data, _ := json.Marshal(tip)
				p.publish("mesh:blocks", string(data), 300)
				p.logger.Info("block tip published", "height", h, "hash", truncateHash(hash))
				lastHeight = h
			}
		}
	}
}

func truncateHash(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}
