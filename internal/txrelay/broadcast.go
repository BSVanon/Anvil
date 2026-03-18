package txrelay

import (
	"fmt"
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/transaction"
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

// Broadcaster handles transaction admission to the local mempool and optionally
// ARC submission. P2P peer relay is not yet implemented — transactions are only
// in the local mempool until peer relay is wired.
type Broadcaster struct {
	mempool *Mempool
	arc     *ARCClient // nil if ARC is disabled
	logger  *slog.Logger
}

// NewBroadcaster creates a new broadcaster.
func NewBroadcaster(mempool *Mempool, arc *ARCClient, logger *slog.Logger) *Broadcaster {
	return &Broadcaster{
		mempool: mempool,
		arc:     arc,
		logger:  logger,
	}
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
	b.mempool.Add(txid, rawBytes)

	result := &BroadcastResult{
		TxID:     txid,
		Accepted: true,
		Message:  "added to local mempool (P2P peer relay not yet implemented)",
	}

	b.logger.Info("mempool admit",
		"txid", txid,
		"size", len(rawBytes),
	)

	return result, nil
}

// BroadcastRaw adds a raw transaction to the local mempool. P2P peer relay
// is NOT yet implemented.
func (b *Broadcaster) BroadcastRaw(raw []byte) (*BroadcastResult, error) {
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("parse raw tx: %w", err)
	}

	txid := tx.TxID().String()
	b.mempool.Add(txid, raw)

	result := &BroadcastResult{
		TxID:     txid,
		Accepted: true,
		Message:  "added to mempool",
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
	if err != nil {
		return &BroadcastResult{
			TxID:    txid,
			ARC:     true,
			Status:  "error",
			Message: fmt.Sprintf("ARC submit failed: %v", err),
		}, nil
	}

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
