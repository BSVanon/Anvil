package txrelay

import (
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Upstream status values — capability-named, not implementation-named, so the
// contract survives the future ARC → Arcade migration without breaking wallet
// consumers that parse these strings.
const (
	UpstreamHealthy  = "healthy"
	UpstreamDegraded = "degraded"
	UpstreamDown     = "down"
)

// BroadcastResult holds the outcome of a transaction broadcast.
type BroadcastResult struct {
	TxID      string `json:"txid"`
	Accepted  bool   `json:"accepted"`
	PeerCount int    `json:"peer_count,omitempty"` // peers that accepted the tx
	ARC       bool   `json:"arc,omitempty"`        // submitted to ARC
	Status    string `json:"status,omitempty"`     // ARC txStatus if applicable
	Message   string `json:"message,omitempty"`
}

// MeshAnnouncer is called when a new transaction should be announced to the mesh.
type MeshAnnouncer func(txid string, size int)

// Broadcaster handles transaction admission to the local mempool, optional
// ARC submission, and mesh announcement to connected peers.
//
// Tracks the timestamps of the most recent ARC success and failure (unix
// seconds, atomic to keep the hot path lock-free) so the heartbeat feed can
// report broadcast-upstream health to federation consumers.
type Broadcaster struct {
	mempool      *Mempool
	arc          *ARCClient    // nil if ARC is disabled
	meshAnnounce MeshAnnouncer // nil if mesh relay is disabled
	logger       *slog.Logger

	arcLastSuccess atomic.Int64 // unix seconds; 0 = never
	arcLastFailure atomic.Int64 // unix seconds; 0 = never
}

// NewBroadcaster creates a new broadcaster.
func NewBroadcaster(mempool *Mempool, arc *ARCClient, logger *slog.Logger) *Broadcaster {
	return &Broadcaster{
		mempool: mempool,
		arc:     arc,
		logger:  logger,
	}
}

// SetMeshAnnouncer sets the callback for announcing txs to the mesh.
// Called after gossip manager is created (avoids circular dependency).
func (b *Broadcaster) SetMeshAnnouncer(fn MeshAnnouncer) {
	b.meshAnnounce = fn
}

// Mempool returns the underlying mempool for direct access.
func (b *Broadcaster) Mempool() *Mempool {
	return b.mempool
}

// BroadcastBEEF extracts the raw transaction from BEEF and adds it to the
// local mempool. P2P peer relay is NOT yet implemented — the tx stays local.
// Returns the result including txid.
func (b *Broadcaster) BroadcastBEEF(beef []byte) (*BroadcastResult, error) {
	tx, err := transaction.NewTransactionFromBEEF(beef)
	if err != nil {
		return nil, fmt.Errorf("parse BEEF for broadcast: %w", err)
	}

	txid := tx.TxID().String()
	rawBytes := tx.Bytes()

	// Add to mempool (idempotent — ignore if already present)
	_ = b.mempool.Add(txid, rawBytes)

	result := &BroadcastResult{
		TxID:     txid,
		Accepted: true,
		Message:  "added to mempool",
	}

	// Announce to mesh peers
	if b.meshAnnounce != nil {
		b.meshAnnounce(txid, len(rawBytes))
	}

	b.logger.Info("mempool admit",
		"txid", txid,
		"size", len(rawBytes),
	)

	return result, nil
}

// BroadcastRaw adds a raw transaction to the local mempool.
func (b *Broadcaster) BroadcastRaw(raw []byte) (*BroadcastResult, error) {
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("parse raw tx: %w", err)
	}

	txid := tx.TxID().String()
	_ = b.mempool.Add(txid, raw) // idempotent — duplicate is not an error

	result := &BroadcastResult{
		TxID:     txid,
		Accepted: true,
		Message:  "added to mempool",
	}

	// Announce to mesh peers
	if b.meshAnnounce != nil {
		b.meshAnnounce(txid, len(raw))
	}

	b.logger.Info("mempool admit raw",
		"txid", txid,
		"size", len(raw),
	)

	return result, nil
}

// BroadcastToARC submits a transaction to ARC for miner acceptance.
// Returns the ARC response including any merkle proof.
func (b *Broadcaster) BroadcastToARC(raw []byte) (*BroadcastResult, error) {
	if b.arc == nil {
		return nil, fmt.Errorf("ARC is not configured")
	}

	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("parse raw tx: %w", err)
	}
	txid := tx.TxID().String()

	resp, err := b.arc.Submit(raw)
	now := time.Now().Unix()
	if err != nil {
		b.arcLastFailure.Store(now)
		return &BroadcastResult{
			TxID:    txid,
			ARC:     true,
			Status:  "error",
			Message: fmt.Sprintf("ARC submit failed: %v", err),
		}, nil
	}
	b.arcLastSuccess.Store(now)

	// ARC returns a txStatus — only certain statuses mean acceptance.
	// SEEN_ON_NETWORK and MINED indicate the tx was accepted.
	// Other statuses (REJECTED, DOUBLE_SPEND_ATTEMPTED, etc.) are failures.
	accepted := resp.Status == "SEEN_ON_NETWORK" || resp.Status == "MINED"

	return &BroadcastResult{
		TxID:     txid,
		Accepted: accepted,
		ARC:      true,
		Status:   resp.Status,
		Message:  fmt.Sprintf("ARC status: %s", resp.Status),
	}, nil
}

// UpstreamStatus returns the current health of the broadcast upstream (ARC
// today, Arcade post-Teranode). Capability-named output; value depends on
// how recently we've seen successful and failed ARC interactions.
//
// Thresholds:
//   - no ARC configured       → "down" (endpoint can't forward to miners)
//   - last success < 5 min    → "healthy"
//   - failure after success within 5 min OR last success 5-30 min ago → "degraded"
//   - last success > 30 min ago (or never, with a recent failure) → "down"
//   - no activity at all yet (success == 0, failure == 0) → "healthy"
//     (assume configured == healthy until proven otherwise; federation nodes
//     with zero broadcast traffic should not be flagged as unreachable)
func (b *Broadcaster) UpstreamStatus() string {
	if b.arc == nil {
		return UpstreamDown
	}
	now := time.Now().Unix()
	lastSuccess := b.arcLastSuccess.Load()
	lastFailure := b.arcLastFailure.Load()

	// No activity yet — trust the configuration
	if lastSuccess == 0 && lastFailure == 0 {
		return UpstreamHealthy
	}

	// If we've never had a success but have a recent failure, we're down.
	if lastSuccess == 0 {
		return UpstreamDown
	}

	successAge := now - lastSuccess
	switch {
	case successAge < 300: // <5 min
		// Recent success. Check for a newer failure as a degradation signal.
		if lastFailure > lastSuccess && (now-lastFailure) < 300 {
			return UpstreamDegraded
		}
		return UpstreamHealthy
	case successAge < 1800: // 5-30 min
		return UpstreamDegraded
	default:
		return UpstreamDown
	}
}
