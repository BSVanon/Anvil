package txrelay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ARCResponse is the response from ARC's transaction submission endpoint.
type ARCResponse struct {
	TxID        string `json:"txid"`
	Status      string `json:"txStatus"` // SEEN_ON_NETWORK, MINED, etc.
	BlockHash   string `json:"blockHash,omitempty"`
	BlockHeight uint32 `json:"blockHeight,omitempty"`
	MerklePath  string `json:"merklePath,omitempty"` // BRC-74 hex if mined
}

// ARCClient is an HTTP client for the ARC transaction processor.
// ARC accepts transactions and returns status + merkle proofs when mined.
type ARCClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewARCClient creates a new ARC client.
func NewARCClient(baseURL, apiKey string) *ARCClient {
	return &ARCClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Submit sends a raw transaction to ARC.
// ARC endpoint: POST /v1/tx
func (c *ARCClient) Submit(raw []byte) (*ARCResponse, error) {
	url := c.baseURL + "/v1/tx"

	body := bytes.NewReader(raw)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ARC request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read ARC response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("ARC returned %d: %s", resp.StatusCode, string(respBody))
	}

	var arcResp ARCResponse
	if err := json.Unmarshal(respBody, &arcResp); err != nil {
		return nil, fmt.Errorf("parse ARC response: %w", err)
	}

	return &arcResp, nil
}

// QueryStatus checks the status of a previously submitted transaction.
// ARC endpoint: GET /v1/tx/{txid}
func (c *ARCClient) QueryStatus(txid string) (*ARCResponse, error) {
	url := c.baseURL + "/v1/tx/" + txid

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ARC request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read ARC response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ARC returned %d: %s", resp.StatusCode, string(respBody))
	}

	var arcResp ARCResponse
	if err := json.Unmarshal(respBody, &arcResp); err != nil {
		return nil, fmt.Errorf("parse ARC response: %w", err)
	}

	return &arcResp, nil
}

// Suppress unused import
var _ = hex.EncodeToString
