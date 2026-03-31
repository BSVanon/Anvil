// Package content serves on-chain inscription data directly from Anvil nodes.
// Eliminates GorillaPool's CDN as a single point of failure for react-onchain
// and all 1Sat ordinal content. Any Anvil node becomes a decentralized CDN.
//
// See STRATEGIC_TOPICS.md Topic 1 and TODO_REMAINING.md.
package content

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// inscription holds parsed inscription data.
type inscription struct {
	ContentType string
	Data        []byte
	FetchedAt   time.Time
}

// TxSource fetches raw transaction hex by txid. Implemented by p2p.TxFetcher.
type TxSource interface {
	FetchRawTx(txid string) (string, error)
}

// BlockTxSource fetches a tx by downloading its containing block. Implemented by p2p.BlockTxFetcher.
type BlockTxSource interface {
	FetchTxFromBlock(txid string, blockHashHex string) (string, error)
	LookupCachedTx(txid string) (string, bool)
}

// Server serves inscription content with a TTL cache (oldest-eviction when full).
type Server struct {
	wocURL       string
	p2pSource    TxSource      // individual tx fetch via P2P
	blockSource  BlockTxSource // block-based tx fetch via P2P (fallback for large txs)
	headerLookup func(height int) string // returns block hash for height
	cache        map[string]*inscription
	mu           sync.RWMutex
	maxAge       time.Duration
	client       *http.Client
}

// NewServer creates a content server.
func NewServer(wocURL string, p2pSource TxSource, blockSource BlockTxSource, headerLookup func(int) string) *Server {
	if wocURL == "" {
		wocURL = "https://api.whatsonchain.com/v1/bsv/main"
	}
	return &Server{
		wocURL:       wocURL,
		p2pSource:    p2pSource,
		blockSource:  blockSource,
		headerLookup: headerLookup,
		cache:        make(map[string]*inscription),
		maxAge:       24 * time.Hour,
		client:       &http.Client{Timeout: 15 * time.Second},
	}
}

// BootstrapBlock pre-fetches an entire block by hash via P2P, caching all transactions.
// GET /content/block/{blockHash} — call once to bootstrap inscriptions from a known block.
func (s *Server) BootstrapBlock(w http.ResponseWriter, r *http.Request) {
	blockHash := r.PathValue("blockHash")
	if len(blockHash) != 64 {
		http.Error(w, "invalid block hash", http.StatusBadRequest)
		return
	}
	if s.blockSource == nil {
		http.Error(w, "block fetching not configured", http.StatusServiceUnavailable)
		return
	}

	// Use a dummy txid — FetchTxFromBlock downloads the whole block and caches all txs
	_, err := s.blockSource.FetchTxFromBlock("0000000000000000000000000000000000000000000000000000000000000000", blockHash)
	// Error is expected (dummy txid won't be found) — but the block is now cached
	if err != nil && !strings.Contains(err.Error(), "not found in block") {
		http.Error(w, fmt.Sprintf("block fetch failed: %v", err), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, `{"status":"ok","block":"%s","message":"block cached, inscriptions now serveable"}`, blockHash)
}

// ServeContent handles GET /content/{origin} where origin is txid_vout.
func (s *Server) ServeContent(w http.ResponseWriter, r *http.Request) {
	origin := r.PathValue("origin")
	if origin == "" {
		http.Error(w, "missing origin", http.StatusBadRequest)
		return
	}

	// Parse origin: txid_vout or txid (default vout=0)
	parts := strings.SplitN(origin, "_", 2)
	txid := parts[0]
	vout := "0"
	if len(parts) == 2 {
		vout = parts[1]
	}

	if len(txid) != 64 {
		http.Error(w, "invalid txid", http.StatusBadRequest)
		return
	}

	cacheKey := txid + "_" + vout

	// Check cache
	s.mu.RLock()
	cached, ok := s.cache[cacheKey]
	s.mu.RUnlock()
	if ok && time.Since(cached.FetchedAt) < s.maxAge {
		serveInscription(w, cached)
		return
	}

	// Fetch raw tx from WoC
	rawHex, err := s.fetchRawTx(txid)
	if err != nil {
		http.Error(w, fmt.Sprintf("fetch tx: %v", err), http.StatusBadGateway)
		return
	}

	// Parse inscription from the specified output
	insc, err := parseInscription(rawHex, vout)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse inscription: %v", err), http.StatusNotFound)
		return
	}

	// Cache
	s.mu.Lock()
	s.cache[cacheKey] = insc
	// Evict old entries if cache grows too large
	if len(s.cache) > 10000 {
		oldest := ""
		oldestTime := time.Now()
		for k, v := range s.cache {
			if v.FetchedAt.Before(oldestTime) {
				oldest = k
				oldestTime = v.FetchedAt
			}
		}
		if oldest != "" {
			delete(s.cache, oldest)
		}
	}
	s.mu.Unlock()

	serveInscription(w, insc)
}

func serveInscription(w http.ResponseWriter, insc *inscription) {
	ct := insc.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(insc.Data)
}

// fetchRawTx gets the raw transaction hex.
// Tries: block cache → P2P individual tx → WoC API → P2P block fetch.
func (s *Server) fetchRawTx(txid string) (string, error) {
	// Check block cache first (instant if block was previously bootstrapped)
	if s.blockSource != nil {
		if rawHex, ok := s.blockSource.LookupCachedTx(txid); ok {
			return rawHex, nil
		}
	}

	// Try P2P individual tx
	if s.p2pSource != nil {
		rawHex, err := s.p2pSource.FetchRawTx(txid)
		if err == nil {
			return rawHex, nil
		}
	}

	// Try WoC API
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
				return rawHex, nil
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
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&proofs); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&tx); err != nil {
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

// fetchRawTxFromWoC gets the raw transaction hex from WhatsOnChain API.
func (s *Server) fetchRawTxFromWoC(txid string) (string, error) {
	url := fmt.Sprintf("%s/tx/%s/hex", s.wocURL, txid)
	resp, err := s.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
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
		if err := json.NewDecoder(resp2.Body).Decode(&txData); err != nil {
			return "", fmt.Errorf("decode tx: %w", err)
		}
		return txData.Hex, nil
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}
	return strings.TrimSpace(buf.String()), nil
}

// parseInscription extracts inscription data from a specific transaction output.
// Parses the raw tx to find the exact output at voutStr, then checks for inscription data.
// Supports two formats:
//   - 1Sat Ordinal: OP_FALSE OP_IF "ord" OP_1 <content-type> OP_0 <data> OP_ENDIF
//   - B:// Protocol: OP_RETURN <B-prefix> <data> <content-type> <encoding>
func parseInscription(rawTxHex string, voutStr string) (*inscription, error) {
	txBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	vout, err := strconv.Atoi(voutStr)
	if err != nil {
		return nil, fmt.Errorf("invalid vout: %w", err)
	}

	// Extract the specific output script
	script, err := extractOutputScript(txBytes, vout)
	if err != nil {
		return nil, fmt.Errorf("extract output %d: %w", vout, err)
	}

	// Try 1Sat Ordinal format first
	if insc := tryParseOrdinal(script); insc != nil {
		return insc, nil
	}

	// Try B:// protocol (OP_RETURN based)
	if insc := tryParseBProtocol(script); insc != nil {
		return insc, nil
	}

	return nil, fmt.Errorf("no inscription found in output %d", vout)
}

// extractOutputScript parses a raw Bitcoin transaction and returns the script at the given output index.
func extractOutputScript(tx []byte, vout int) ([]byte, error) {
	if len(tx) < 10 {
		return nil, fmt.Errorf("transaction too short")
	}

	pos := 4 // skip version (4 bytes)

	// Read input count (varint)
	inputCount, n := readVarInt(tx[pos:])
	pos += n

	// Skip all inputs
	if inputCount > uint64(len(tx)) {
		return nil, fmt.Errorf("input count %d exceeds tx length", inputCount)
	}
	for i := uint64(0); i < inputCount; i++ {
		pos += 32 // prev txid
		pos += 4  // prev vout
		scriptLen, n := readVarInt(tx[pos:])
		pos += n
		if scriptLen > uint64(len(tx)-pos) { // #nosec G115 // len()-pos is non-negative here
			return nil, fmt.Errorf("input %d script length exceeds tx boundary", i)
		}
		pos += int(scriptLen) // #nosec G115 // bounded by len(tx) via check above
		pos += 4              // sequence
		if pos > len(tx) {
			return nil, fmt.Errorf("input %d exceeds tx boundary", i)
		}
	}

	// Read output count (varint)
	outputCount, n := readVarInt(tx[pos:])
	pos += n

	if outputCount > uint64(len(tx)) {
		return nil, fmt.Errorf("output count %d exceeds tx length", outputCount)
	}
	if vout < 0 || uint64(vout) >= outputCount {
		return nil, fmt.Errorf("vout %d out of range (output count %d)", vout, outputCount)
	}

	// Read outputs until we reach the target vout
	for i := uint64(0); i < outputCount; i++ {
		if pos+8 > len(tx) {
			return nil, fmt.Errorf("output %d exceeds tx boundary", i)
		}
		pos += 8 // satoshi value (8 bytes)
		scriptLen, n := readVarInt(tx[pos:])
		pos += n

		if scriptLen > uint64(len(tx)-pos) { // #nosec G115 // len()-pos is non-negative here
			return nil, fmt.Errorf("output %d script length exceeds tx boundary", i)
		}

		if i == uint64(vout) {
			return tx[pos : pos+int(scriptLen)], nil // #nosec G115 // bounded by len(tx) via check above
		}
		pos += int(scriptLen) // #nosec G115 // bounded by len(tx) via check above
	}

	return nil, fmt.Errorf("output %d not found", vout)
}

// readVarInt reads a Bitcoin-style compact size integer.
func readVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}
	first := data[0]
	switch {
	case first < 0xfd:
		return uint64(first), 1
	case first == 0xfd:
		if len(data) < 3 {
			return 0, 1
		}
		return uint64(binary.LittleEndian.Uint16(data[1:3])), 3
	case first == 0xfe:
		if len(data) < 5 {
			return 0, 1
		}
		return uint64(binary.LittleEndian.Uint32(data[1:5])), 5
	default: // 0xff
		if len(data) < 9 {
			return 0, 1
		}
		return binary.LittleEndian.Uint64(data[1:9]), 9
	}
}

// tryParseOrdinal looks for OP_FALSE OP_IF "ord" pattern.
func tryParseOrdinal(txBytes []byte) *inscription {
	marker := []byte{0x00, 0x63, 0x03, 0x6f, 0x72, 0x64}
	idx := bytes.Index(txBytes, marker)
	if idx < 0 {
		return nil
	}

	pos := idx + len(marker)
	insc := &inscription{FetchedAt: time.Now()}

	for pos < len(txBytes) {
		op := txBytes[pos]
		pos++

		switch {
		case op == 0x51: // OP_1 — content-type
			data, newPos, err := readPush(txBytes, pos)
			if err != nil {
				return nil
			}
			insc.ContentType = string(data)
			pos = newPos
		case op == 0x00: // OP_0 — file data
			data, newPos, err := readPush(txBytes, pos)
			if err != nil {
				return nil
			}
			insc.Data = data
			pos = newPos
		case op == 0x68: // OP_ENDIF
			if insc.Data != nil {
				return insc
			}
			return nil
		}
	}
	if insc.Data != nil {
		return insc
	}
	return nil
}

// tryParseBProtocol looks for OP_RETURN followed by B:// protocol data.
// B:// format: OP_RETURN <B-address> <data> <content-type> [<encoding>]
// The B address is "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
func tryParseBProtocol(txBytes []byte) *inscription {
	// Find OP_RETURN (0x6a)
	idx := bytes.Index(txBytes, []byte{0x6a})
	if idx < 0 {
		return nil
	}

	pos := idx + 1
	// Read all pushes after OP_RETURN
	var pushes [][]byte
	for pos < len(txBytes) {
		data, newPos, err := readPush(txBytes, pos)
		if err != nil {
			break
		}
		pushes = append(pushes, data)
		pos = newPos
	}

	// B:// protocol: push[0] = B address, push[1] = data, push[2] = content-type
	bAddr := "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
	if len(pushes) >= 3 && string(pushes[0]) == bAddr {
		return &inscription{
			ContentType: string(pushes[2]),
			Data:        pushes[1],
			FetchedAt:   time.Now(),
		}
	}

	// Fallback: if first push looks like it contains the B address + separator
	if len(pushes) >= 1 {
		first := string(pushes[0])
		if strings.Contains(first, bAddr) && len(pushes) >= 3 {
			return &inscription{
				ContentType: string(pushes[2]),
				Data:        pushes[1],
				FetchedAt:   time.Now(),
			}
		}
	}

	return nil
}

// readPush reads a Bitcoin script push data element at the given position.
func readPush(data []byte, pos int) ([]byte, int, error) {
	if pos >= len(data) {
		return nil, pos, fmt.Errorf("unexpected end")
	}

	op := data[pos]
	pos++

	switch {
	case op >= 0x01 && op <= 0x4b: // direct push (1-75 bytes)
		end := pos + int(op)
		if end > len(data) {
			return nil, pos, fmt.Errorf("push exceeds data")
		}
		return data[pos:end], end, nil

	case op == 0x4c: // OP_PUSHDATA1
		if pos >= len(data) {
			return nil, pos, fmt.Errorf("missing length byte")
		}
		length := int(data[pos])
		pos++
		end := pos + length
		if end > len(data) {
			return nil, pos, fmt.Errorf("pushdata1 exceeds data")
		}
		return data[pos:end], end, nil

	case op == 0x4d: // OP_PUSHDATA2
		if pos+1 >= len(data) {
			return nil, pos, fmt.Errorf("missing length bytes")
		}
		length := int(data[pos]) | int(data[pos+1])<<8
		pos += 2
		end := pos + length
		if end > len(data) {
			return nil, pos, fmt.Errorf("pushdata2 exceeds data")
		}
		return data[pos:end], end, nil

	case op == 0x4e: // OP_PUSHDATA4
		if pos+3 >= len(data) {
			return nil, pos, fmt.Errorf("missing length bytes")
		}
		length := int(data[pos]) | int(data[pos+1])<<8 | int(data[pos+2])<<16 | int(data[pos+3])<<24
		pos += 4
		end := pos + length
		if end > len(data) {
			return nil, pos, fmt.Errorf("pushdata4 exceeds data")
		}
		return data[pos:end], end, nil

	default:
		return nil, pos, fmt.Errorf("expected push op, got 0x%02x", op)
	}
}
