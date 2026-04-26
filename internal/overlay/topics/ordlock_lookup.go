package topics

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay"
	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// OrdLockLookupServiceName is the BRC-87 lookup service name.
const OrdLockLookupServiceName = "ls_ordlock_listings"

const (
	ordlockDefaultLimit = 100
	ordlockMaxLimit     = 500
)

// OrdLockQuery is the wire query shape for ls_ordlock_listings.
// Field naming follows N2/N3 in docs/internal/ORDLOCK_TOPIC_REQUEST.md.
type OrdLockQuery struct {
	List          string `json:"list,omitempty"`          // "all" returns everything
	TokenId       string `json:"tokenId,omitempty"`       // filter to single BSV-21
	Tick          string `json:"tick,omitempty"`          // filter to BSV-20 (case-insensitive)
	CancelAddress string `json:"cancelAddress,omitempty"` // filter by seller's cancel-key (base58check)
	Limit         int    `json:"limit,omitempty"`         // default 100, max 500
	Offset        int    `json:"offset,omitempty"`        // default 0
}

// OrdLockLookupService implements overlay.LookupService for OrdLock listings.
type OrdLockLookupService struct {
	engine *overlay.Engine
}

// NewOrdLockLookupService creates an OrdLock lookup service.
func NewOrdLockLookupService(engine *overlay.Engine) *OrdLockLookupService {
	return &OrdLockLookupService{engine: engine}
}

// Lookup answers an OrdLock listings query. See OrdLockQuery for the wire shape.
func (ls *OrdLockLookupService) Lookup(queryRaw json.RawMessage) (*overlay.LookupAnswer, error) {
	var q OrdLockQuery
	if err := json.Unmarshal(queryRaw, &q); err != nil {
		return nil, fmt.Errorf("invalid OrdLock query: %w", err)
	}

	// Pre-resolve cancelAddress to a 20-byte pkh hex once.
	cancelPkhFilter, err := normalizeCancelFilter(q.CancelAddress)
	if err != nil {
		return nil, err
	}

	// Normalize tick (case-insensitive — N3).
	tickFilter := strings.ToUpper(strings.TrimSpace(q.Tick))

	outputs, err := ls.engine.GetOutputsByTopic(OrdLockTopicName)
	if err != nil {
		return nil, err
	}

	matches := make([]overlay.AdmittedOutput, 0, len(outputs))
	matchEntries := make([]OrdLockEntry, 0, len(outputs))
	for _, out := range outputs {
		var entry OrdLockEntry
		if err := json.Unmarshal(out.Metadata, &entry); err != nil {
			continue
		}
		if !matchesOrdLockQuery(entry, q.TokenId, tickFilter, cancelPkhFilter) {
			continue
		}
		matches = append(matches, out)
		matchEntries = append(matchEntries, entry)
	}

	// Default sort: AdmittedAt descending (newest-first per N3). RFC3339 UTC
	// is lexicographically sortable, so a string sort gives correct ordering.
	indexed := make([]int, len(matches))
	for i := range indexed {
		indexed[i] = i
	}
	sort.SliceStable(indexed, func(a, b int) bool {
		return matchEntries[indexed[a]].AdmittedAt > matchEntries[indexed[b]].AdmittedAt
	})

	sorted := make([]overlay.AdmittedOutput, len(matches))
	for i, idx := range indexed {
		sorted[i] = matches[idx]
	}

	// Pagination.
	limit, offset := normalizeLimitOffset(q.Limit, q.Offset)
	if offset >= len(sorted) {
		return &overlay.LookupAnswer{Type: "output-list", Outputs: nil}, nil
	}
	end := offset + limit
	if end > len(sorted) {
		end = len(sorted)
	}

	return &overlay.LookupAnswer{
		Type:    "output-list",
		Outputs: sorted[offset:end],
	}, nil
}

// matchesOrdLockQuery applies the filter rules. tokenId + tick are mutually
// exclusive — if tokenId is supplied we ignore tick (per N3).
func matchesOrdLockQuery(entry OrdLockEntry, tokenId, tickUpper, cancelPkhFilterLower string) bool {
	switch {
	case tokenId != "":
		if !strings.EqualFold(entry.TokenId, tokenId) {
			return false
		}
	case tickUpper != "":
		if entry.Tick != tickUpper {
			return false
		}
	}
	if cancelPkhFilterLower != "" {
		if !strings.EqualFold(entry.CancelPkhHex, cancelPkhFilterLower) {
			return false
		}
	}
	return true
}

// normalizeCancelFilter converts a mainnet base58check P2PKH address to a
// 20-byte pkh hex string. Empty input → empty filter (no-op). Invalid input
// (testnet/regtest prefixes, wrong length, bad SHA256d checksum, or any
// non-base58 characters) is a query error so callers learn their request is
// malformed rather than silently getting empty results.
//
// Three checks, all required:
//  1. Length: 25 bytes (1 version + 20 pkh + 4 checksum).
//  2. Version: 0x00 (mainnet P2PKH only). 0x6f (testnet) is rejected because
//     this surface is mainnet-only and a testnet address would otherwise
//     silently match a mainnet listing on the bare 20-byte pkh.
//  3. Checksum: SHA256d of the first 21 bytes must equal the trailing 4
//     bytes. Without this a payload that just happens to start with 0x00
//     and be 25 bytes long would pass validation.
//
// Decoding raw rather than via script.NewAddressFromString because that helper
// accepts both 0x00 and 0x6f prefixes; we want strict mainnet-only rejection.
func normalizeCancelFilter(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", nil
	}
	decoded, err := base58.Decode(addr)
	if err != nil {
		return "", fmt.Errorf("invalid cancelAddress %q: %w", addr, err)
	}
	if len(decoded) != 25 {
		return "", fmt.Errorf("cancelAddress %q is not a 25-byte base58check payload", addr)
	}
	if decoded[0] != 0x00 {
		return "", fmt.Errorf("cancelAddress %q is not a mainnet P2PKH (version=0x%02x)", addr, decoded[0])
	}
	want := crypto.Sha256d(decoded[:21])[:4]
	if !bytes.Equal(want, decoded[21:25]) {
		return "", fmt.Errorf("cancelAddress %q has an invalid base58check checksum", addr)
	}
	pkh := decoded[1:21]
	return strings.ToLower(hex.EncodeToString(pkh)), nil
}

func normalizeLimitOffset(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = ordlockDefaultLimit
	}
	if limit > ordlockMaxLimit {
		limit = ordlockMaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// GetDocumentation returns a description of the OrdLock lookup service.
func (ls *OrdLockLookupService) GetDocumentation() string {
	return "OrdLock Listings Lookup: Query active 1Sat OrdLock fixed-price listings. Filter by tokenId (BSV-21), tick (BSV-20), or cancelAddress; paginate via limit/offset; default sort is admittedAt descending."
}

// GetMetadata returns machine-readable metadata about the lookup service.
func (ls *OrdLockLookupService) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"service": OrdLockLookupServiceName,
		"queries": []string{"list", "tokenId", "tick", "cancelAddress", "limit", "offset"},
	}
}

// Compile-time conformance check.
var _ overlay.LookupService = (*OrdLockLookupService)(nil)
