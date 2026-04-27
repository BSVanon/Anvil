package topics

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay"
)

// OrdLockBuyLookupServiceName is the BRC-87 lookup service name for buy vaults.
const OrdLockBuyLookupServiceName = "ls_ordlock_buy_vaults"

const (
	ordlockBuyDefaultLimit = 100
	ordlockBuyMaxLimit     = 500
)

// OrdLockBuyQuery is the wire query shape for ls_ordlock_buy_vaults.
type OrdLockBuyQuery struct {
	List          string `json:"list,omitempty"`          // "all" returns everything
	TokenId       string `json:"tokenId,omitempty"`       // filter to single BSV-21
	Tick          string `json:"tick,omitempty"`          // filter to BSV-20 (case-insensitive)
	CancelAddress string `json:"cancelAddress,omitempty"` // filter by buyer's cancel-key (base58check)
	Outpoint      string `json:"outpoint,omitempty"`      // filter to a single outpoint
	Limit         int    `json:"limit,omitempty"`         // default 100, max 500
	Offset        int    `json:"offset,omitempty"`        // default 0
}

// OrdLockBuyLookupService implements overlay.LookupService for OrdLockBuy vaults.
type OrdLockBuyLookupService struct {
	engine *overlay.Engine
}

// NewOrdLockBuyLookupService creates a lookup service for OrdLockBuy vaults.
func NewOrdLockBuyLookupService(engine *overlay.Engine) *OrdLockBuyLookupService {
	return &OrdLockBuyLookupService{engine: engine}
}

// Lookup answers an OrdLockBuy vaults query.
func (ls *OrdLockBuyLookupService) Lookup(queryRaw json.RawMessage) (*overlay.LookupAnswer, error) {
	var q OrdLockBuyQuery
	if err := json.Unmarshal(queryRaw, &q); err != nil {
		return nil, fmt.Errorf("invalid OrdLockBuy query: %w", err)
	}

	cancelPkhFilter, err := normalizeCancelFilter(q.CancelAddress)
	if err != nil {
		return nil, err
	}
	tickFilter := strings.ToUpper(strings.TrimSpace(q.Tick))
	outpointFilter := strings.TrimSpace(q.Outpoint)

	outputs, err := ls.engine.GetOutputsByTopic(OrdLockBuyTopicName)
	if err != nil {
		return nil, err
	}

	matches := make([]overlay.AdmittedOutput, 0, len(outputs))
	matchEntries := make([]OrdLockBuyEntry, 0, len(outputs))
	for _, out := range outputs {
		var entry OrdLockBuyEntry
		if err := json.Unmarshal(out.Metadata, &entry); err != nil {
			continue
		}
		if !matchesOrdLockBuyQuery(entry, q.TokenId, tickFilter, cancelPkhFilter, outpointFilter) {
			continue
		}
		matches = append(matches, out)
		matchEntries = append(matchEntries, entry)
	}

	// Default sort: AdmittedAt descending (newest-first).
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

	limit, offset := normalizeOrdLockBuyLimitOffset(q.Limit, q.Offset)
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

// matchesOrdLockBuyQuery applies the filter rules. tokenId + tick are
// mutually exclusive — if tokenId is supplied we ignore tick.
func matchesOrdLockBuyQuery(entry OrdLockBuyEntry, tokenId, tickUpper, cancelPkhFilterLower, outpointFilter string) bool {
	if outpointFilter != "" {
		if !strings.EqualFold(entry.Outpoint, outpointFilter) {
			return false
		}
	}
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

func normalizeOrdLockBuyLimitOffset(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = ordlockBuyDefaultLimit
	}
	if limit > ordlockBuyMaxLimit {
		limit = ordlockBuyMaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// GetDocumentation returns a description of the OrdLockBuy lookup service.
func (ls *OrdLockBuyLookupService) GetDocumentation() string {
	return "OrdLockBuy Vaults Lookup: Query active free-agent buy-side OrdLock vaults. Filter by tokenId (BSV-21), tick (BSV-20), cancelAddress (the buyer's), or a specific outpoint; paginate via limit/offset; default sort is admittedAt descending."
}

// GetMetadata returns machine-readable metadata about the lookup service.
func (ls *OrdLockBuyLookupService) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"service": OrdLockBuyLookupServiceName,
		"queries": []string{"list", "tokenId", "tick", "cancelAddress", "outpoint", "limit", "offset"},
	}
}

// Compile-time conformance check.
var _ overlay.LookupService = (*OrdLockBuyLookupService)(nil)
