package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	wtkwallet "github.com/bsv-blockchain/go-wallet-toolbox/pkg/wallet"
)

// wocUTXO is an unspent output from the WhatsOnChain API.
type wocUTXO struct {
	TxHash string `json:"tx_hash"`
	TxPos  uint32 `json:"tx_pos"`
	Value  uint64 `json:"value"`
	Height int64  `json:"height"`
}

// wocUnspentResponse is the wrapper returned by WoC's /unspent/all endpoint.
type wocUnspentResponse struct {
	Result []wocUTXO `json:"result"`
	Error  string    `json:"error"`
}

// ScanResult summarizes a UTXO scan operation.
type ScanResult struct {
	Address       string       `json:"address"`
	UTXOsFound    int          `json:"utxos_found"`
	Internalized  int          `json:"internalized"`
	AlreadyKnown  int          `json:"already_known"`
	Errors        int          `json:"errors"`
	TotalSatoshis uint64       `json:"total_satoshis"`
	Details       []ScanDetail `json:"details,omitempty"`
}

// ScanDetail is the per-UTXO outcome of a scan.
type ScanDetail struct {
	TxID     string `json:"txid"`
	Vout     uint32 `json:"vout"`
	Satoshis uint64 `json:"satoshis"`
	Status   string `json:"status"` // "internalized", "already_known", "skipped", "error"
	Error    string `json:"error,omitempty"`
}

// Scanner discovers UTXOs at the node's identity address and internalizes
// them into the wallet as BEEF. This bridges the gap where external payments
// (from other wallets, exchanges, etc.) land on-chain but are invisible to
// go-wallet-toolbox because they weren't received as BEEF.
type Scanner struct {
	inner       *wtkwallet.Wallet
	identityKey *ec.PrivateKey
	arcClient   *txrelay.ARCClient
	logger      *slog.Logger
	httpClient  *http.Client
}

// NewScanner creates a UTXO scanner for the node's identity address.
func NewScanner(
	inner *wtkwallet.Wallet,
	identityKey *ec.PrivateKey,
	arcClient *txrelay.ARCClient,
	logger *slog.Logger,
) *Scanner {
	return &Scanner{
		inner:       inner,
		identityKey: identityKey,
		arcClient:   arcClient,
		logger:      logger,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Scan queries WhatsOnChain for UTXOs at the identity address, fetches
// merkle proofs from ARC, builds BEEF, and internalizes each into the wallet.
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	addr, err := script.NewAddressFromPublicKey(s.identityKey.PubKey(), true)
	if err != nil {
		return nil, fmt.Errorf("derive address: %w", err)
	}
	return s.ScanAddress(ctx, addr.AddressString)
}

// ScanAddress queries WhatsOnChain for UTXOs at the given address, fetches
// merkle proofs from ARC, builds BEEF, and internalizes each into the wallet.
// Use this for invoice-derived addresses or any address the node's WIF controls.
func (s *Scanner) ScanAddress(ctx context.Context, address string) (*ScanResult, error) {
	s.logger.Info("scanner: starting UTXO scan", "address", address)

	// Query WhatsOnChain for unspent outputs
	utxos, err := s.fetchUTXOs(address)
	if err != nil {
		return nil, fmt.Errorf("fetch UTXOs from WhatsOnChain: %w", err)
	}

	result := &ScanResult{
		Address:    address,
		UTXOsFound: len(utxos),
	}

	if len(utxos) == 0 {
		s.logger.Info("scanner: no UTXOs found", "address", address)
		return result, nil
	}

	// 3. Check which UTXOs the wallet already knows about
	knownSet := s.buildKnownSet(ctx)

	// 4. For each unknown confirmed UTXO: fetch raw tx + merkle proof → BEEF → internalize
	for _, utxo := range utxos {
		detail := ScanDetail{
			TxID:     utxo.TxHash,
			Vout:     utxo.TxPos,
			Satoshis: utxo.Value,
		}

		key := fmt.Sprintf("%s:%d", utxo.TxHash, utxo.TxPos)
		if knownSet[key] {
			detail.Status = "already_known"
			result.AlreadyKnown++
			result.Details = append(result.Details, detail)
			continue
		}

		// Must be confirmed to have a merkle proof
		if utxo.Height <= 0 {
			detail.Status = "skipped"
			detail.Error = "unconfirmed — need merkle proof for BEEF"
			result.Details = append(result.Details, detail)
			continue
		}

		// Fetch raw transaction hex from WhatsOnChain
		rawTxHex, err := s.fetchRawTx(utxo.TxHash)
		if err != nil {
			detail.Status = "error"
			detail.Error = fmt.Sprintf("fetch raw tx: %v", err)
			result.Errors++
			result.Details = append(result.Details, detail)
			continue
		}

		// Parse transaction to get canonical TxID hash
		txBytesRaw, txParseErr := hex.DecodeString(rawTxHex)
		if txParseErr != nil {
			detail.Status = "error"
			detail.Error = fmt.Sprintf("decode raw tx: %v", txParseErr)
			result.Errors++
			result.Details = append(result.Details, detail)
			continue
		}
		parsedTx, txParseErr := transaction.NewTransactionFromBytes(txBytesRaw)
		if txParseErr != nil {
			detail.Status = "error"
			detail.Error = fmt.Sprintf("parse tx: %v", txParseErr)
			result.Errors++
			result.Details = append(result.Details, detail)
			continue
		}

		// Fetch merkle proof (tries ARC then WoC TSC fallback)
		merkleHex, err := s.fetchMerkleProof(utxo.TxHash, uint32(utxo.Height))
		if err != nil {
			detail.Status = "error"
			detail.Error = fmt.Sprintf("fetch merkle proof: %v", err)
			result.Errors++
			result.Details = append(result.Details, detail)
			continue
		}

		// Build BEEF from parsed tx + merkle path
		beefBytes, err := buildBEEFFromTx(parsedTx, merkleHex)
		if err != nil {
			detail.Status = "error"
			detail.Error = fmt.Sprintf("build BEEF: %v", err)
			result.Errors++
			result.Details = append(result.Details, detail)
			continue
		}

		// Import the P2PKH UTXO into the wallet using createAction + signAction.
		// This mirrors wallet-toolbox's fundWalletFromP2PKHOutpoints approach:
		// pass the external BEEF as inputBEEF and spend the UTXO in one step,
		// rather than internalizing first (which fails to register proof chains).
		outpoint := transaction.Outpoint{Txid: *parsedTx.TxID(), Index: utxo.TxPos}
		trustSelf := sdk.TrustSelf("known")
		car, err := s.inner.CreateAction(ctx, sdk.CreateActionArgs{
			Description: fmt.Sprintf("Import P2PKH UTXO %s:%d", utxo.TxHash[:16], utxo.TxPos),
			InputBEEF:   beefBytes,
			Inputs: []sdk.CreateActionInput{
				{
					Outpoint:              outpoint,
					InputDescription:      "fund wallet from P2PKH",
					UnlockingScriptLength: 108, // standard P2PKH unlock size
				},
			},
			Labels: []string{"p2pkh-funding"},
			Options: &sdk.CreateActionOptions{
				TrustSelf: trustSelf,
			},
		}, "anvil-scanner")
		if err != nil {
			detail.Status = "error"
			detail.Error = fmt.Sprintf("create action: %v", err)
			result.Errors++
			result.Details = append(result.Details, detail)
			continue
		}

		// If wallet auto-signed (no signableTransaction), we're done.
		// Otherwise, sign the P2PKH input and complete via signAction.
		if car.SignableTransaction != nil {
			err = s.signAndComplete(ctx, car, parsedTx, utxo)
			if err != nil {
				detail.Status = "error"
				detail.Error = fmt.Sprintf("sign action: %v", err)
				result.Errors++
				result.Details = append(result.Details, detail)
				continue
			}
		}

		detail.Status = "internalized"
		result.Internalized++
		result.TotalSatoshis += utxo.Value
		result.Details = append(result.Details, detail)

		s.logger.Info("scanner: internalized UTXO",
			"txid", utxo.TxHash,
			"vout", utxo.TxPos,
			"satoshis", utxo.Value,
		)
	}

	s.logger.Info("scanner: scan complete",
		"found", result.UTXOsFound,
		"internalized", result.Internalized,
		"already_known", result.AlreadyKnown,
		"errors", result.Errors,
		"total_sats", result.TotalSatoshis,
	)

	return result, nil
}

// signAndComplete signs the P2PKH input in a signable transaction and completes
// the action via SignAction. This handles the case where createAction returns
// a signable transaction instead of auto-signing.
func (s *Scanner) signAndComplete(ctx context.Context, car *sdk.CreateActionResult, parsedTx *transaction.Transaction, utxo wocUTXO) error {
	st := car.SignableTransaction

	// Find our input in the signable transaction
	// SignableTransaction.Tx is BEEF format, not raw tx bytes
	stTx := &transaction.Transaction{}
	if err := stTx.FromBEEF(st.Tx); err != nil {
		return fmt.Errorf("parse signable tx from BEEF: %w", err)
	}

	inputIndex := -1
	for i, inp := range stTx.Inputs {
		if inp.SourceTXID != nil && inp.SourceTXID.Equal(*parsedTx.TxID()) && inp.SourceTxOutIndex == utxo.TxPos {
			inputIndex = i
			break
		}
	}
	if inputIndex < 0 {
		return fmt.Errorf("could not find outpoint in signable transaction inputs")
	}

	// Sign the P2PKH input
	satoshis := parsedTx.Outputs[utxo.TxPos].Satoshis
	unlock, err := p2pkh.Unlock(s.identityKey, nil)
	if err != nil {
		return fmt.Errorf("create unlock template: %w", err)
	}
	stTx.Inputs[inputIndex].UnlockingScriptTemplate = unlock
	stTx.Inputs[inputIndex].SourceTransaction = parsedTx
	if err := stTx.Sign(); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	_ = satoshis // used implicitly by the unlock template via SourceTransaction

	unlockScript := stTx.Inputs[inputIndex].UnlockingScript.Bytes()

	// Complete via SignAction
	spends := make(map[uint32]sdk.SignActionSpend)
	spends[uint32(inputIndex)] = sdk.SignActionSpend{
		UnlockingScript: unlockScript,
	}
	_, err = s.inner.SignAction(ctx, sdk.SignActionArgs{
		Reference: st.Reference,
		Spends:    spends,
	}, "anvil-scanner")
	if err != nil {
		return fmt.Errorf("sign action: %w", err)
	}

	return nil
}

// buildKnownSet returns a set of "txid:vout" strings for outputs the wallet
// already tracks, so we can skip them during scanning.
func (s *Scanner) buildKnownSet(ctx context.Context) map[string]bool {
	known := make(map[string]bool)
	listResult, err := s.inner.ListOutputs(ctx, sdk.ListOutputsArgs{
		Basket: "default",
	}, "anvil-scanner")
	if err != nil {
		s.logger.Warn("scanner: list existing outputs failed, will re-scan all", "error", err)
		return known
	}
	for _, out := range listResult.Outputs {
		key := fmt.Sprintf("%s:%d", out.Outpoint.Txid, out.Outpoint.Index)
		known[key] = true
	}
	return known
}

// fetchUTXOs queries WhatsOnChain for unspent outputs at the given address.
func (s *Scanner) fetchUTXOs(address string) ([]wocUTXO, error) {
	url := "https://api.whatsonchain.com/v1/bsv/main/address/" + address + "/unspent/all"
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WoC returned %d: %s", resp.StatusCode, string(body))
	}

	var wrapped wocUnspentResponse
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("parse UTXOs: %w", err)
	}
	if wrapped.Error != "" {
		return nil, fmt.Errorf("WoC error: %s", wrapped.Error)
	}
	return wrapped.Result, nil
}

// fetchRawTx fetches the raw transaction hex from WhatsOnChain.
func (s *Scanner) fetchRawTx(txid string) (string, error) {
	url := "https://api.whatsonchain.com/v1/bsv/main/tx/" + txid + "/hex"
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("WoC returned %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// fetchMerkleProof gets a merkle proof for a confirmed tx.
// Tries ARC first (BRC-74 hex), falls back to WhatsOnChain TSC format.
func (s *Scanner) fetchMerkleProof(txid string, blockHeight uint32) (string, error) {
	// Try ARC first
	if s.arcClient != nil {
		arcResp, err := s.arcClient.QueryStatus(txid)
		if err == nil && arcResp.MerklePath != "" {
			return arcResp.MerklePath, nil
		}
	}

	// Fall back to WhatsOnChain TSC proof
	return s.fetchMerkleProofFromWoC(txid, blockHeight)
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
func (s *Scanner) fetchMerkleProofFromWoC(txid string, blockHeight uint32) (string, error) {
	url := "https://api.whatsonchain.com/v1/bsv/main/tx/" + txid + "/proof/tsc"
	resp, err := s.httpClient.Get(url)
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

	// Convert TSC to BRC-74 using go-sdk's VarInt + MerklePath types.
	// TSC: index (leaf position), nodes[] (sibling hashes bottom-to-top).
	// Hashes from WoC are in display (reversed) order — we reverse to
	// natural byte order for chainhash.NewHash (which does NOT reverse).

	treeHeight := len(proof.Nodes)

	// Build the path levels
	path := make([][]*transaction.PathElement, treeHeight)
	offset := proof.Index

	// Derive the canonical txid hash from the raw transaction bytes.
	// We must NOT use proof.TxOrID decoded from hex — the go-sdk's chainhash
	// internal byte order differs from manual hex decode + reverse.
	txidHash, _ := chainhash.NewHashFromHex(proof.TxOrID)

	for level := 0; level < treeHeight; level++ {
		sibOffset := offset ^ 1

		if level == 0 {
			isTrue := true

			var elements []*transaction.PathElement

			// Add both in offset order (lower first)
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
			// Levels 1+: just the sibling
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
	reverseBytes(nodeBytes) // display → natural byte order
	h, _ := chainhash.NewHash(nodeBytes)
	return &transaction.PathElement{Offset: offset, Hash: h}
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// buildBEEFFromTx constructs Atomic BEEF from an already-parsed transaction
// and a BRC-74 merkle path hex string.
func buildBEEFFromTx(tx *transaction.Transaction, merklePathHex string) ([]byte, error) {
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

// buildLockingScript returns the P2PKH locking script for an address.
// Exported for use by the scan handler.
func buildLockingScript(addr *script.Address) ([]byte, error) {
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, err
	}
	return []byte(*lockScript), nil
}
