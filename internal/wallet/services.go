package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk"
	"github.com/libsv/go-p2p/wire"
)

// AnvilServices implements wdk.Services, bridging go-wallet-toolbox to
// Anvil's header store, proof store, and broadcast infrastructure.
type AnvilServices struct {
	headerStore *headers.Store
	proofStore  *spv.ProofStore
	broadcaster *txrelay.Broadcaster
}

// NewAnvilServices creates a Services adapter for go-wallet-toolbox.
func NewAnvilServices(
	headerStore *headers.Store,
	proofStore *spv.ProofStore,
	broadcaster *txrelay.Broadcaster,
) *AnvilServices {
	return &AnvilServices{
		headerStore: headerStore,
		proofStore:  proofStore,
		broadcaster: broadcaster,
	}
}

// --- chaintracker.ChainTracker ---

func (s *AnvilServices) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	return s.headerStore.IsValidRootForHeight(ctx, root, height)
}

func (s *AnvilServices) CurrentHeight(ctx context.Context) (uint32, error) {
	return s.headerStore.CurrentHeight(ctx)
}

// --- BlockHeaderLoader ---

func (s *AnvilServices) ChainHeaderByHeight(ctx context.Context, height uint32) (*wdk.ChainBlockHeader, error) {
	raw, err := s.headerStore.HeaderAtHeight(height)
	if err != nil {
		return nil, fmt.Errorf("header at %d: %w", height, err)
	}

	var hdr wire.BlockHeader
	if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("deserialize header at %d: %w", height, err)
	}

	blockHash := hdr.BlockHash()

	return &wdk.ChainBlockHeader{
		ChainBaseBlockHeader: wdk.ChainBaseBlockHeader{
			Version:      uint32(max(0, int64(hdr.Version))),      // #nosec G115 // clamped non-negative, block versions fit uint32
			PreviousHash: hdr.PrevBlock.String(),
			MerkleRoot:   hdr.MerkleRoot.String(),
			Time:         uint32(max(0, hdr.Timestamp.Unix())), // #nosec G115 // clamped non-negative, block timestamps fit uint32 until 2106
			Bits:         hdr.Bits,
			Nonce:        hdr.Nonce,
		},
		Height: uint(height),
		Hash:   blockHash.String(),
	}, nil
}

// --- Services methods ---

func (s *AnvilServices) PostFromBEEF(ctx context.Context, beef *transaction.Beef, txids []string) (wdk.PostFromBeefResult, error) {
	if s.broadcaster == nil {
		return nil, fmt.Errorf("broadcaster not configured")
	}

	// Broadcast each tx in the BEEF through Anvil's broadcaster.
	// The broadcaster adds to mempool (and eventually relays to P2P peers).
	var txResults []wdk.PostedTxID
	for _, txid := range txids {
		tx := beef.FindTransaction(txid)
		if tx == nil {
			txResults = append(txResults, wdk.PostedTxID{
				Result: wdk.PostedTxIDResultError,
				TxID:   txid,
				Error:  fmt.Errorf("tx %s not found in BEEF", txid),
			})
			continue
		}

		raw := tx.Bytes()
		br, err := s.broadcaster.BroadcastRaw(raw)
		if err != nil {
			txResults = append(txResults, wdk.PostedTxID{
				Result: wdk.PostedTxIDResultError,
				TxID:   txid,
				Error:  err,
			})
			continue
		}

		txResults = append(txResults, wdk.PostedTxID{
			Result: wdk.PostedTxIDResultSuccess,
			TxID:   br.TxID,
		})
	}

	return wdk.PostFromBeefResult{
		&wdk.PostFromBEEFServiceResult{
			Name: "anvil",
			PostedBEEFResult: &wdk.PostedBEEF{
				TxIDResults: txResults,
			},
		},
	}, nil
}

func (s *AnvilServices) MerklePath(ctx context.Context, txid string) (*wdk.MerklePathResult, error) {
	beefBytes, err := s.proofStore.GetBEEF(txid)
	if err != nil {
		return &wdk.MerklePathResult{Name: "anvil"}, nil
	}
	tx, err := transaction.NewTransactionFromBEEF(beefBytes)
	if err != nil {
		return &wdk.MerklePathResult{Name: "anvil"}, nil
	}
	return &wdk.MerklePathResult{
		Name:       "anvil",
		MerklePath: tx.MerklePath,
	}, nil
}

func (s *AnvilServices) FindChainTipHeader(ctx context.Context) (*wdk.ChainBlockHeader, error) {
	tip := s.headerStore.Tip()
	return s.ChainHeaderByHeight(ctx, tip)
}

func (s *AnvilServices) RawTx(ctx context.Context, txID string) (wdk.RawTxResult, error) {
	beefBytes, err := s.proofStore.GetBEEF(txID)
	if err != nil {
		return wdk.RawTxResult{TxID: txID, Name: "anvil"}, nil
	}
	tx, err := transaction.NewTransactionFromBEEF(beefBytes)
	if err != nil {
		return wdk.RawTxResult{TxID: txID, Name: "anvil"}, nil
	}
	return wdk.RawTxResult{
		TxID:  txID,
		Name:  "anvil",
		RawTx: tx.Bytes(),
	}, nil
}

func (s *AnvilServices) GetBEEF(ctx context.Context, txID string, knownTxIDs []string) (*transaction.Beef, error) {
	beefBytes, err := s.proofStore.GetBEEF(txID)
	if err != nil {
		return nil, fmt.Errorf("BEEF not found for %s", txID)
	}
	return transaction.NewBeefFromBytes(beefBytes)
}

func (s *AnvilServices) NLockTimeIsFinal(ctx context.Context, txOrLockTime any) (bool, error) {
	// For simplicity, treat all transactions as final
	return true, nil
}

func (s *AnvilServices) GetStatusForTxIDs(ctx context.Context, txIDs []string) (*wdk.GetStatusForTxIDsResult, error) {
	var details []wdk.TxStatusDetail
	for _, txid := range txIDs {
		status := "unknown"
		if s.proofStore.HasBEEF(txid) {
			status = "completed"
		}
		details = append(details, wdk.TxStatusDetail{
			TxID:   txid,
			Status: status,
		})
	}
	return &wdk.GetStatusForTxIDsResult{
		Name:    "anvil",
		Results: details,
	}, nil
}

// Suppress unused imports
var _ = hex.EncodeToString
