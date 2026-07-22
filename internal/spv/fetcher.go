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

// BEEF source constants — identifies which upstream supplied a fetched proof.
// "cached" is set by the caller when the ProofStore was hit directly; the fetcher
// itself never returns "cached" because it only runs on cache miss.
const (
	BEEFSourceCached = "cached"
	BEEFSourceARC    = "arc"
	BEEFSourceWoC    = "woc"
)

// FetchBEEF fetches a raw transaction and its merkle proof from external
// sources, builds Atomic BEEF, and returns the binary plus the source
// ("arc" or "woc") that supplied the merkle proof. Returns an error if the
// transaction is not found or has no confirmed proof yet.
func (f *ProofFetcher) FetchBEEF(txid string) ([]byte, string, error) {
	// 1. Fetch raw transaction hex from WhatsOnChain
	rawHex, err := f.fetchRawTx(txid)
	if err != nil {
		return nil, "", fmt.Errorf("fetch raw tx: %w", err)
	}

	// 2. Parse to get the Transaction object
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, "", fmt.Errorf("decode raw tx hex: %w", err)
	}
	tx, err := transaction.NewTransactionFromBytes(rawBytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse raw tx: %w", err)
	}

	// 3. Get block height from ARC or WoC to know where to look for proof
	blockHeight, err := f.fetchBlockHeight(txid)
	if err != nil {
		return nil, "", fmt.Errorf("tx not confirmed or height unknown: %w", err)
	}
	if blockHeight == 0 {
		return nil, "", fmt.Errorf("tx %s is unconfirmed — no merkle proof available", txid)
	}

	// 4. Fetch merkle proof (ARC first, WoC fallback). The source tracks which
	// upstream actually supplied the proof so callers can report it to consumers.
	merkleHex, source, err := f.fetchMerkleProof(txid, blockHeight)
	if err != nil {
		return nil, "", fmt.Errorf("fetch merkle proof: %w", err)
	}

	// 5. Build Atomic BEEF
	beefBytes, err := buildBEEF(tx, merkleHex)
	if err != nil {
		return nil, "", fmt.Errorf("build BEEF: %w", err)
	}

	f.logger.Info("fetched BEEF on demand", "txid", txid, "block", blockHeight, "size", len(beefBytes), "source", source)
	return beefBytes, source, nil
}

// TxStatusResult is the resolved chain status of a txid from upstream sources.
// Found distinguishes "known to the network (mempool or mined)" from "not found".
// Status carries a canonical ARC-style txStatus string (passed through verbatim
// when ARC answered; synthesized as MINED/SEEN_ON_NETWORK from a block-height-only
// source). This is a lightweight status probe — it does NOT build or verify a
// merkle proof (use FetchBEEF for that).
type TxStatusResult struct {
	Found       bool   // tx is known to an upstream (mempool or mined)
	Mined       bool   // tx has a confirmed block height
	BlockHeight uint32 // block height if mined, else 0
	Status      string // canonical ARC txStatus (e.g. MINED, SEEN_ON_NETWORK)
	Source      string // upstream that answered: BEEFSourceARC | BEEFSourceWoC
}

// syntheticStatus maps a block-height-only signal (WhatsOnChain has no status
// string) onto the minimal canonical ARC txStatus vocabulary.
func syntheticStatus(mined bool) string {
	if mined {
		return "MINED"
	}
	return "SEEN_ON_NETWORK"
}

// TxStatus resolves whether a txid is mined and at what height, trying ARC first
// (fast, no external explorer) then WhatsOnChain. When ARC answers, its canonical
// txStatus is passed through verbatim (so DOUBLE_SPEND_ATTEMPTED,
// MINED_IN_STALE_BLOCK, etc. surface); the WoC fallback synthesizes
// MINED/SEEN_ON_NETWORK. A returned error means both sources were unusable
// (upstream outage) — callers should surface that as a 5xx, NOT as "not found".
// A found-but-unmined tx returns {Found:true} with a nil error; a genuinely
// unknown tx returns {Found:false} with a nil error.
func (f *ProofFetcher) TxStatus(txid string) (*TxStatusResult, error) {
	// ARC first — if ARC knows the tx at all, its response is authoritative for
	// status/height. An ARC error (404 unknown, or unreachable) falls through to
	// WoC rather than being treated as "not found".
	if f.arcClient != nil {
		if arcResp, err := f.arcClient.QueryStatus(txid); err == nil && arcResp != nil {
			status := arcResp.Status
			// "Mined" means confirmed on the ACTIVE chain. ARC's MINED is
			// active-chain; MINED_IN_STALE_BLOCK (and every other status) may
			// carry a blockHeight but is NOT an active-chain confirmation — so a
			// blockHeight>0 heuristic would wrongly report confirmations for an
			// orphaned tx. Only fall back to that heuristic when ARC gave no
			// status string at all.
			var mined bool
			if status != "" {
				// A real MINED needs an active-chain height to derive
				// confirmations from; MINED without a height (blockHeight omits
				// to 0 on absent JSON), or any non-MINED status, is not a usable
				// confirmation.
				mined = status == "MINED" && arcResp.BlockHeight > 0
			} else {
				mined = arcResp.BlockHeight > 0
				status = syntheticStatus(mined)
			}
			blockHeight := uint32(0)
			if mined {
				blockHeight = arcResp.BlockHeight
			}
			return &TxStatusResult{
				Found:       true,
				Mined:       mined,
				BlockHeight: blockHeight,
				Status:      status,
				Source:      BEEFSourceARC,
			}, nil
		}
	}
	return f.txStatusFromWoC(txid)
}

// txStatusFromWoC resolves tx status from WhatsOnChain's tx-info endpoint.
// A 404 is a definitive "not found" (nil error); any other non-200 is an
// upstream failure (returned as an error so the caller emits a 5xx).
func (f *ProofFetcher) txStatusFromWoC(txid string) (*TxStatusResult, error) {
	url := f.wocBaseURL + "/tx/" + txid
	resp, err := f.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("WoC tx info request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read WoC tx info: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return &TxStatusResult{Found: false}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WoC returned %d", resp.StatusCode)
	}

	var info struct {
		BlockHeight int64 `json:"blockheight"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse WoC tx info: %w", err)
	}
	// Present in WoC but blockheight <= 0 (or out of uint32 range) = mempool/unconfirmed.
	if info.BlockHeight <= 0 || info.BlockHeight > int64(^uint32(0)) {
		return &TxStatusResult{Found: true, Mined: false, Status: syntheticStatus(false), Source: BEEFSourceWoC}, nil
	}
	return &TxStatusResult{Found: true, Mined: true, BlockHeight: uint32(info.BlockHeight), Status: syntheticStatus(true), Source: BEEFSourceWoC}, nil
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
	if info.BlockHeight <= 0 || info.BlockHeight > int64(^uint32(0)) {
		return 0, nil // unconfirmed or out of uint32 range
	}
	return uint32(info.BlockHeight), nil
}

// fetchMerkleProof gets a merkle proof for a confirmed tx.
// Tries ARC first (BRC-74 hex), falls back to WhatsOnChain TSC format.
// Returns (merkle_hex, source, err) — source is "arc" or "woc".
func (f *ProofFetcher) fetchMerkleProof(txid string, blockHeight uint32) (string, string, error) {
	if f.arcClient != nil {
		arcResp, err := f.arcClient.QueryStatus(txid)
		if err == nil && arcResp.MerklePath != "" {
			return arcResp.MerklePath, BEEFSourceARC, nil
		}
	}
	mp, err := f.fetchMerkleProofFromWoC(txid, blockHeight)
	if err != nil {
		return "", "", err
	}
	return mp, BEEFSourceWoC, nil
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
