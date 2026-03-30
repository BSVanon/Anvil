package spv

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ProofFetcher fetches raw transactions and merkle proofs from external
// sources (ARC, WhatsOnChain) and builds Atomic BEEF envelopes. This is a
// stateless service — caching is handled by the caller (typically via ProofStore).
type ProofFetcher struct {
	arcClient  *txrelay.ARCClient
	httpClient *http.Client
	logger     *slog.Logger
	wocBaseURL string // overridable for testing; defaults to WoC mainnet
}

// NewProofFetcher creates a proof fetcher. arcClient may be nil (WoC-only mode).
func NewProofFetcher(arcClient *txrelay.ARCClient, logger *slog.Logger) *ProofFetcher {
	return &ProofFetcher{
		arcClient:  arcClient,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
		wocBaseURL: "https://api.whatsonchain.com/v1/bsv/main",
	}
}

// SetBaseURL overrides the WoC base URL (for testing).
func (f *ProofFetcher) SetBaseURL(base string) {
	f.wocBaseURL = base
}

// FetchBEEF fetches a raw transaction and its merkle proof from external
// sources, builds Atomic BEEF, and returns the binary. Returns an error if the
// transaction is not found or has no confirmed proof yet.
func (f *ProofFetcher) FetchBEEF(txid string) ([]byte, error) {
	// 1. Fetch raw transaction hex from WhatsOnChain
	rawHex, err := f.fetchRawTx(txid)
	if err != nil {
		return nil, fmt.Errorf("fetch raw tx: %w", err)
	}

	// 2. Parse to get the Transaction object
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("decode raw tx hex: %w", err)
	}
	tx, err := transaction.NewTransactionFromBytes(rawBytes)
	if err != nil {
		return nil, fmt.Errorf("parse raw tx: %w", err)
	}

	// 3. Get block height from ARC or WoC to know where to look for proof
	blockHeight, err := f.fetchBlockHeight(txid)
	if err != nil {
		return nil, fmt.Errorf("tx not confirmed or height unknown: %w", err)
	}
	if blockHeight == 0 {
		return nil, fmt.Errorf("tx %s is unconfirmed — no merkle proof available", txid)
	}

	// 4. Fetch merkle proof (ARC first, WoC fallback)
	merkleHex, err := f.fetchMerkleProof(txid, blockHeight)
	if err != nil {
		return nil, fmt.Errorf("fetch merkle proof: %w", err)
	}

	// 5. Build Atomic BEEF
	beefBytes, err := buildBEEF(tx, merkleHex)
	if err != nil {
		return nil, fmt.Errorf("build BEEF: %w", err)
	}

	f.logger.Info("fetched BEEF on demand", "txid", txid, "block", blockHeight, "size", len(beefBytes))
	return beefBytes, nil
}

// fetchRawTx fetches the raw transaction hex from WhatsOnChain.
func (f *ProofFetcher) fetchRawTx(txid string) (string, error) {
	url := f.wocBaseURL + "/tx/" + txid + "/hex"
	resp, err := f.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("transaction not found")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("WoC returned %d: %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

// fetchBlockHeight determines the confirmed block height for a txid.
// Tries ARC first, falls back to WoC tx info.
func (f *ProofFetcher) fetchBlockHeight(txid string) (uint32, error) {
	// Try ARC
	if f.arcClient != nil {
		arcResp, err := f.arcClient.QueryStatus(txid)
		if err == nil && arcResp.BlockHeight > 0 {
			return arcResp.BlockHeight, nil
		}
	}

	// Fall back to WoC
	url := f.wocBaseURL + "/tx/" + txid
	resp, err := f.httpClient.Get(url)
	if err != nil {
		return 0, fmt.Errorf("WoC tx info request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("read WoC tx info: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("WoC returned %d", resp.StatusCode)
	}

	var info struct {
		BlockHeight int64 `json:"blockheight"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return 0, fmt.Errorf("parse WoC tx info: %w", err)
	}
	if info.BlockHeight <= 0 {
		return 0, nil // unconfirmed
	}
	return uint32(info.BlockHeight), nil
}

// fetchMerkleProof gets a merkle proof for a confirmed tx.
// Tries ARC first (BRC-74 hex), falls back to WhatsOnChain TSC format.
func (f *ProofFetcher) fetchMerkleProof(txid string, blockHeight uint32) (string, error) {
	if f.arcClient != nil {
		arcResp, err := f.arcClient.QueryStatus(txid)
		if err == nil && arcResp.MerklePath != "" {
			return arcResp.MerklePath, nil
		}
	}
	return f.fetchMerkleProofFromWoC(txid, blockHeight)
}

// tscProof is a single TSC merkle proof entry from WhatsOnChain.
type tscProof struct {
	Index  uint64   `json:"index"`
	TxOrID string   `json:"txOrId"`
	Target string   `json:"target"`
	Nodes  []string `json:"nodes"`
}

// fetchMerkleProofFromWoC fetches a TSC merkle proof from WhatsOnChain
// and converts it to BRC-74 hex format for BEEF construction.
func (f *ProofFetcher) fetchMerkleProofFromWoC(txid string, blockHeight uint32) (string, error) {
	url := f.wocBaseURL + "/tx/" + txid + "/proof/tsc"
	resp, err := f.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("WoC TSC request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read WoC TSC response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("WoC TSC returned %d: %s", resp.StatusCode, string(body))
	}

	var proofs []tscProof
	if err := json.Unmarshal(body, &proofs); err != nil {
		return "", fmt.Errorf("parse TSC proof: %w", err)
	}
	if len(proofs) == 0 {
		return "", fmt.Errorf("no TSC proof returned for %s", txid)
	}

	proof := proofs[0]
	treeHeight := len(proof.Nodes)
	path := make([][]*transaction.PathElement, treeHeight)
	offset := proof.Index

	txidHash, _ := chainhash.NewHashFromHex(proof.TxOrID)

	for level := 0; level < treeHeight; level++ {
		sibOffset := offset ^ 1

		if level == 0 {
			isTrue := true
			var elements []*transaction.PathElement
			if offset < sibOffset {
				elements = append(elements, &transaction.PathElement{
					Offset: offset, Hash: txidHash, Txid: &isTrue,
				})
				elements = append(elements, tscNodeToElement(proof.Nodes[0], sibOffset))
			} else {
				elements = append(elements, tscNodeToElement(proof.Nodes[0], sibOffset))
				elements = append(elements, &transaction.PathElement{
					Offset: offset, Hash: txidHash, Txid: &isTrue,
				})
			}
			path[0] = elements
		} else {
			path[level] = []*transaction.PathElement{
				tscNodeToElement(proof.Nodes[level], sibOffset),
			}
		}
		offset = offset / 2
	}

	mp := transaction.NewMerklePath(blockHeight, path)
	return hex.EncodeToString(mp.Bytes()), nil
}

// tscNodeToElement converts a TSC node hash (or "*" duplicate) to a PathElement.
func tscNodeToElement(node string, offset uint64) *transaction.PathElement {
	if node == "*" {
		dup := true
		return &transaction.PathElement{Offset: offset, Duplicate: &dup}
	}
	nodeBytes, _ := hex.DecodeString(node)
	reverseBytes(nodeBytes)
	h, _ := chainhash.NewHash(nodeBytes)
	return &transaction.PathElement{Offset: offset, Hash: h}
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// buildBEEF constructs Atomic BEEF from a parsed transaction and BRC-74 merkle path hex.
func buildBEEF(tx *transaction.Transaction, merklePathHex string) ([]byte, error) {
	mp, err := transaction.NewMerklePathFromHex(merklePathHex)
	if err != nil {
		return nil, fmt.Errorf("parse merkle path: %w", err)
	}
	tx.MerklePath = mp

	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		return nil, fmt.Errorf("build beef from tx: %w", err)
	}
	atomicBytes, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		return nil, fmt.Errorf("serialize atomic BEEF: %w", err)
	}
	return atomicBytes, nil
}
