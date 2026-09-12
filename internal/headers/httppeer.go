package headers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

// httpMaxHeadersPerReq mirrors the peer's /headers/range cap (api.MaxHeadersRange
// = 50). Fetches are batched to stay within it.
const httpMaxHeadersPerReq = 50

// HTTPHeaderSource pulls block headers from a peer Anvil node's HTTP header API
// (GET /headers/tip + GET /headers/range). It backs the header-sync fallback:
// when a node cannot reach its BSV P2P peers, it catches up over HTTPS from a
// TRUSTED, operator-configured Anvil peer (config header_fallback_peers).
//
// Every fetched header still passes the store's PoW (hash ≤ its stated target) +
// prev-hash linkage + cumulative most-work validation (AddHeaders / ReorgTo) —
// the same path a native BSV peer's headers take. That rejects a minority
// (lower-work) chain and any header failing its own stated target, but it does
// NOT verify difficulty-adjustment (DAA) correctness or a min-difficulty floor.
// So a configured fallback peer is trusted to the SAME degree as a configured
// [bsv] node — which is exactly why these peers are opt-in and explicit, not
// auto-discovered from mesh gossip.
type HTTPHeaderSource struct {
	baseURL string
	client  *http.Client
}

// NewHTTPHeaderSource builds a source for the given Anvil HTTP base URL
// (e.g. https://anvil.sendbsv.com).
func NewHTTPHeaderSource(baseURL string) *HTTPHeaderSource {
	return &HTTPHeaderSource{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Tip returns the peer's current header height.
func (h *HTTPHeaderSource) Tip() (uint32, error) {
	resp, err := h.client.Get(h.baseURL + "/headers/tip")
	if err != nil {
		return 0, fmt.Errorf("get tip: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("tip: HTTP %d", resp.StatusCode)
	}
	var body struct {
		Height uint32 `json:"height"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode tip: %w", err)
	}
	return body.Height, nil
}

// HeadersFrom fetches up to count (capped at 50) raw 80-byte block headers
// starting at height `from`, parsed into wire.BlockHeader.
func (h *HTTPHeaderSource) HeadersFrom(from, count uint32) ([]*wire.BlockHeader, error) {
	if count == 0 {
		return nil, nil
	}
	if count > httpMaxHeadersPerReq {
		count = httpMaxHeadersPerReq
	}
	url := fmt.Sprintf("%s/headers/range?from=%d&count=%d", h.baseURL, from, count)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get range %d/%d: %w", from, count, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("range %d/%d: HTTP %d", from, count, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(count)*80+1024))
	if err != nil {
		return nil, fmt.Errorf("read range: %w", err)
	}
	// Require EXACTLY the requested count. The syncer's forward-catch-up loop
	// applies each batch at store.Tip()+1, so a peer returning fewer (or more)
	// than asked would desync heights — reject rather than trust the length.
	if len(raw) != int(count)*80 {
		return nil, fmt.Errorf("range %d/%d: expected exactly %d bytes, got %d", from, count, int(count)*80, len(raw))
	}
	n := int(count)
	hdrs := make([]*wire.BlockHeader, 0, n)
	for i := 0; i < n; i++ {
		var hdr wire.BlockHeader
		if err := hdr.Deserialize(bytes.NewReader(raw[i*80 : (i+1)*80])); err != nil {
			return nil, fmt.Errorf("parse header %d: %w", i, err)
		}
		hdrs = append(hdrs, &hdr)
	}
	return hdrs, nil
}

// HashAt returns the peer's block hash at a single height.
func (h *HTTPHeaderSource) HashAt(height uint32) (*chainhash.Hash, error) {
	hdrs, err := h.HeadersFrom(height, 1)
	if err != nil {
		return nil, err
	}
	if len(hdrs) != 1 {
		return nil, fmt.Errorf("expected 1 header at %d, got %d", height, len(hdrs))
	}
	hash := hdrs[0].BlockHash()
	return &hash, nil
}
