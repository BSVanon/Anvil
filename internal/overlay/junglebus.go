package overlay

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/BSVanon/Anvil/pkg/brc"
	"github.com/GorillaPool/go-junglebus"
	"github.com/GorillaPool/go-junglebus/models"
	sdkoverlay "github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
)

// JungleBusSubscriber subscribes to JungleBus for real-time SHIP/SLAP token
// detection. This is the canonical live discovery transport per ARCHITECTURE.md.
type JungleBusSubscriber struct {
	client     *junglebus.Client
	discoverer *Discoverer
	logger     *slog.Logger
	subID      string
	fromBlock  uint64
}

// NewJungleBusSubscriber creates a new JungleBus subscriber for overlay discovery.
func NewJungleBusSubscriber(
	serverURL string,
	subID string,
	fromBlock uint64,
	discoverer *Discoverer,
	logger *slog.Logger,
) (*JungleBusSubscriber, error) {
	client, err := junglebus.New(
		junglebus.WithHTTP(serverURL),
	)
	if err != nil {
		return nil, fmt.Errorf("create junglebus client: %w", err)
	}

	return &JungleBusSubscriber{
		client:     client,
		discoverer: discoverer,
		logger:     logger,
		subID:      subID,
		fromBlock:  fromBlock,
	}, nil
}

// Start begins the JungleBus subscription. Blocks until context is cancelled.
func (s *JungleBusSubscriber) Start(ctx context.Context) error {
	handler := &junglebus.EventHandler{
		OnTransaction: s.onTransaction,
		OnMempool:     s.onTransaction, // process mempool txs too
		OnStatus: func(resp *models.ControlResponse) {
			s.logger.Info("junglebus status",
				"block", resp.GetBlock(),
				"status", resp.GetStatusCode(),
			)
		},
		OnError: func(err error) {
			s.logger.Error("junglebus error", "error", err)
		},
	}

	s.logger.Info("starting junglebus subscription",
		"subscription_id", s.subID,
		"from_block", s.fromBlock,
	)

	_, err := s.client.Subscribe(ctx, s.subID, s.fromBlock, *handler)
	if err != nil {
		return fmt.Errorf("junglebus subscribe: %w", err)
	}

	// Block until context cancelled
	<-ctx.Done()
	_ = s.client.Unsubscribe() // best-effort cleanup on shutdown
	return nil
}

// onTransaction processes a transaction from JungleBus, scanning outputs
// for SHIP/SLAP BRC-48 tokens and feeding them into the discoverer.
func (s *JungleBusSubscriber) onTransaction(txResp *models.TransactionResponse) {
	rawTx := txResp.GetTransaction()
	if len(rawTx) == 0 {
		return
	}

	tx, err := transaction.NewTransactionFromBytes(rawTx)
	if err != nil {
		return // not a valid tx
	}

	txid := tx.TxID().String()

	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}

		// Try to decode as a BRC-48 push-drop token
		pd := pushdrop.Decode(out.LockingScript)
		if pd == nil || len(pd.Fields) < 4 {
			continue
		}

		protocol := string(pd.Fields[0])
		switch protocol {
		case string(sdkoverlay.ProtocolSHIP):
			scriptBytes := []byte(*out.LockingScript)
			if err := s.discoverer.ProcessSHIPScript(scriptBytes, txid, i); err != nil {
				s.logger.Debug("junglebus: invalid SHIP token",
					"txid", txid,
					"output", i,
					"error", err,
				)
			} else {
				s.logger.Info("junglebus: discovered SHIP token",
					"txid", txid,
					"output", i,
					"identity", hex.EncodeToString(pd.Fields[1])[:16],
				)
			}

		case string(sdkoverlay.ProtocolSLAP):
			scriptBytes := []byte(*out.LockingScript)
			if err := s.discoverer.ProcessSLAPScript(scriptBytes, txid, i); err != nil {
				s.logger.Debug("junglebus: invalid SLAP token",
					"txid", txid,
					"output", i,
					"error", err,
				)
			} else {
				s.logger.Info("junglebus: discovered SLAP token",
					"txid", txid,
					"output", i,
				)
			}
		}
	}
}

// Suppress unused imports
var _ = brc.InvoiceSHIP
var _ = script.NewFromBytes
