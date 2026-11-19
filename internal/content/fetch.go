package content

import (
	"fmt"
	"net/http"
	"strings"
)

// This file holds Server's remote-fetch logic — the sources fetchRawTx
// tries, in order, to get a transaction's raw hex: the block cache, a
// single-tx P2P fetch, WhatsOnChain (hex endpoint then JSON fallback), and a
// P2P block fetch. serve.go holds HTTP serving and inscription parsing.

// fetchRawTx gets the raw transaction hex.
// Tries: block cache → P2P individual tx → WoC API → P2P block fetch.
// Every source is checked with verifyTxidMatch before its bytes are
// accepted: a mismatch is treated exactly like that source failing, so
// fetchRawTx moves on to the next one rather than ever returning (and so
// ServeContent ever caching or serving) bytes that are not the requested tx.
func (s *Server) fetchRawTx(txid string) (string, error) {
	// Check block cache first (instant if block was previously bootstrapped)
	if s.blockSource != nil {
		if rawHex, ok := s.blockSource.LookupCachedTx(txid); ok {
			if verr := verifyTxidMatch(rawHex, txid); verr == nil {
				return rawHex, nil
			}
			logTxidMismatch("block_cache", txid)
		}
	}

	// Try P2P individual tx
	if s.p2pSource != nil {
		rawHex, err := s.p2pSource.FetchRawTx(txid)
		if err == nil {
			if verr := verifyTxidMatch(rawHex, txid); verr == nil {
				return rawHex, nil
			}
			logTxidMismatch("p2p_tx", txid)
		}
	}

	// Try WoC API (verified internally — see fetchRawTxFromWoC)
	rawHex, err := s.fetchRawTxFromWoC(txid)
	if err == nil {
		return rawHex, nil
	}

	// Last resort: fetch from block via P2P
	if s.blockSource != nil {
		blockHash := s.findBlockHash(txid)
		if blockHash != "" {
			rawHex, err := s.blockSource.FetchTxFromBlock(txid, blockHash)
			if err == nil {
				if verr := verifyTxidMatch(rawHex, txid); verr == nil {
					return rawHex, nil
				}
				logTxidMismatch("p2p_block", txid)
			}
		}

		// If we have a cached block that might contain this tx (same-block siblings),
		// the BlockTxFetcher's cache will handle it automatically on retry.
	}

	return "", fmt.Errorf("all sources failed for tx %s", txid)
}

// findBlockHash tries to determine which block contains a transaction.
// Tries multiple WoC endpoints since large txs may not be indexed on all of them.
func (s *Server) findBlockHash(txid string) string {
	// Try 1: WoC tx status (works for normal txs)
	if hash := s.tryWoCStatus(txid); hash != "" {
		return hash
	}

	// Try 2: WoC TSC proof — the "target" field is the block hash
	if hash := s.tryWoCProof(txid); hash != "" {
		return hash
	}

	// Try 3: WoC confirmation endpoint
	if hash := s.tryWoCConfirmation(txid); hash != "" {
		return hash
	}

	return ""
}

func (s *Server) tryWoCStatus(txid string) string {
	url := fmt.Sprintf("%s/tx/%s/status", s.wocURL, txid)
	resp, err := s.client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var status struct {
		BlockHeight int    `json:"block_height"`
		BlockHash   string `json:"block_hash"`
	}
	if err := decodeWoCMetadata(resp.Body, &status); err != nil {
		return ""
	}
	if status.BlockHash != "" {
		return status.BlockHash
	}
	if status.BlockHeight > 0 && s.headerLookup != nil {
		return s.headerLookup(status.BlockHeight)
	}
	return ""
}

func (s *Server) tryWoCProof(txid string) string {
	url := fmt.Sprintf("%s/tx/%s/proof/tsc", s.wocURL, txid)
	resp, err := s.client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	// TSC proof can be an array or single object
	var proofs []struct {
		Target string `json:"target"`
	}
	if err := decodeWoCMetadata(resp.Body, &proofs); err != nil {
		return ""
	}
	if len(proofs) > 0 && proofs[0].Target != "" {
		return proofs[0].Target
	}
	return ""
}

func (s *Server) tryWoCConfirmation(txid string) string {
	// Try the basic tx endpoint which sometimes includes blockheight
	url := fmt.Sprintf("%s/tx/%s", s.wocURL, txid)
	resp, err := s.client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var tx struct {
		BlockHeight int    `json:"blockheight"`
		BlockHash   string `json:"blockhash"`
	}
	if err := decodeWoCMetadata(resp.Body, &tx); err != nil {
		return ""
	}
	if tx.BlockHash != "" {
		return tx.BlockHash
	}
	if tx.BlockHeight > 0 && s.headerLookup != nil {
		return s.headerLookup(tx.BlockHeight)
	}
	return ""
}

// fetchRawTxFromWoC gets the raw transaction hex from WhatsOnChain API,
// verified against txid. The dedicated hex endpoint is tried first; a
// non-200 status, or a 200 reply whose bytes don't hash to txid, falls
// through to the JSON endpoint's embedded hex field, which is verified the
// same way before being returned.
func (s *Server) fetchRawTxFromWoC(txid string) (string, error) {
	url := fmt.Sprintf("%s/tx/%s/hex", s.wocURL, txid)
	resp, err := s.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := readWoCBody(resp.Body)
		if err != nil {
			return "", err
		}
		rawHex := strings.TrimSpace(string(body))
		if verr := verifyTxidMatch(rawHex, txid); verr == nil {
			return rawHex, nil
		}
		logTxidMismatch("whatsonchain_hex", txid)
		// Bytes didn't hash to txid — fall through to the JSON endpoint
		// below, same as a non-200 status would.
	}

	// Try JSON endpoint as fallback
	url2 := fmt.Sprintf("%s/tx/%s", s.wocURL, txid)
	resp2, err := s.client.Get(url2)
	if err != nil {
		return "", fmt.Errorf("WoC returned %d", resp.StatusCode)
	}
	defer resp2.Body.Close()
	var txData struct {
		Hex string `json:"hex"`
	}
	if err := decodeWoCJSON(resp2.Body, &txData); err != nil {
		return "", fmt.Errorf("decode tx: %w", err)
	}
	rawHex := strings.TrimSpace(txData.Hex)
	if verr := verifyTxidMatch(rawHex, txid); verr != nil {
		logTxidMismatch("whatsonchain_json", txid)
		return "", verr
	}
	return rawHex, nil
}
