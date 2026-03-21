// Package bond verifies that a peer has a bond UTXO locked at their identity address.
// This is a day-1 requirement before the mesh opens to public nodes — nodes without
// economic skin in the game cannot peer. See STRATEGIC_TOPICS.md Topic 2/11.
package bond

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
)

const bondCacheTTL = 1 * time.Hour

// cacheEntry holds a cached bond verification result.
type cacheEntry struct {
	balance   int
	err       error
	expiresAt time.Time
}

const defaultWoCURL = "https://api.whatsonchain.com/v1/bsv/main"

// Checker verifies bond UTXOs for peer identity keys.
type Checker struct {
	minSats int
	apiURL  string
	client  *http.Client

	cacheMu sync.RWMutex
	cache   map[string]cacheEntry // pubkey hex → cached result
}

// NewChecker creates a bond checker. If minSats is 0, all peers are accepted.
func NewChecker(minSats int, apiURL string) *Checker {
	if apiURL == "" {
		apiURL = defaultWoCURL
	}
	return &Checker{
		minSats: minSats,
		apiURL:  apiURL,
		client:  &http.Client{Timeout: 10 * time.Second},
		cache:   make(map[string]cacheEntry),
	}
}

// Required returns true if bond checking is enabled.
func (c *Checker) Required() bool {
	return c.minSats > 0
}

// MinSats returns the minimum bond requirement.
func (c *Checker) MinSats() int {
	return c.minSats
}

// wocUTXO matches the WhatsOnChain unspent/all response format.
type wocUTXO struct {
	TxHash string `json:"tx_hash"`
	TxPos  int    `json:"tx_pos"`
	Value  int    `json:"value"`
	Height int    `json:"height"`
}

type wocResponse struct {
	Result []wocUTXO `json:"result"`
}

// VerifyBond checks that the identity key has at least minSats in confirmed UTXOs.
// Returns (totalBalance, nil) on success or (0, error) on failure.
// Results are cached for 1 hour to avoid redundant WoC HTTP requests.
func (c *Checker) VerifyBond(identityPub *ec.PublicKey) (int, error) {
	if c.minSats <= 0 {
		return 0, nil // bond not required
	}

	cacheKey := hex.EncodeToString(identityPub.Compressed())

	// Check cache first
	c.cacheMu.RLock()
	if entry, ok := c.cache[cacheKey]; ok && time.Now().Before(entry.expiresAt) {
		c.cacheMu.RUnlock()
		return entry.balance, entry.err
	}
	c.cacheMu.RUnlock()

	balance, err := c.verifyBondHTTP(identityPub)

	// Cache the result (both success and failure)
	c.cacheMu.Lock()
	c.cache[cacheKey] = cacheEntry{
		balance:   balance,
		err:       err,
		expiresAt: time.Now().Add(bondCacheTTL),
	}
	c.cacheMu.Unlock()

	return balance, err
}

// verifyBondHTTP performs the actual WoC HTTP lookup (uncached).
func (c *Checker) verifyBondHTTP(identityPub *ec.PublicKey) (int, error) {
	address, err := pubKeyToAddress(identityPub)
	if err != nil {
		return 0, fmt.Errorf("derive address: %w", err)
	}

	url := fmt.Sprintf("%s/address/%s/unspent/all", c.apiURL, address)
	resp, err := c.client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch UTXOs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("WoC returned %d for address %s", resp.StatusCode, address)
	}

	var data wocResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		// Try as raw array (WoC sometimes returns array directly)
		resp2, err2 := c.client.Get(url)
		if err2 != nil {
			return 0, fmt.Errorf("decode UTXOs: %w", err)
		}
		defer resp2.Body.Close()
		var utxos []wocUTXO
		if err := json.NewDecoder(resp2.Body).Decode(&utxos); err != nil {
			return 0, fmt.Errorf("decode UTXOs: %w", err)
		}
		data.Result = utxos
	}

	total := 0
	for _, u := range data.Result {
		if u.Height > 0 { // only confirmed UTXOs count as bond
			total += u.Value
		}
	}

	if total < c.minSats {
		return total, fmt.Errorf("insufficient bond: %d sats (need %d) at %s", total, c.minSats, address)
	}

	return total, nil
}

// pubKeyToAddress derives a P2PKH address from a compressed public key.
func pubKeyToAddress(pub *ec.PublicKey) (string, error) {
	addr, err := script.NewAddressFromPublicKey(pub, true)
	if err != nil {
		return "", err
	}
	return addr.AddressString, nil
}
