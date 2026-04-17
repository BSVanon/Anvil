package topics

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay"
)

// DEXSwapLookupServiceName is the BRC-87 standard name for the DEX swap lookup service.
const DEXSwapLookupServiceName = "ls_dex_swap"

// DEXSwapLookupQuery supports filtered queries for active swap offers.
type DEXSwapLookupQuery struct {
	// List returns all active offers. Value: "all"
	List string `json:"list,omitempty"`
	// OfferingTokenTxid filters by the offered token's genesis txid.
	OfferingTokenTxid string `json:"offering_token_txid,omitempty"`
	// RequestingTokenTxid filters by the requested token's genesis txid.
	RequestingTokenTxid string `json:"requesting_token_txid,omitempty"`
	// Maker filters by the maker's public key (hex).
	Maker string `json:"maker,omitempty"`
}

// DEXSwapLookupService implements overlay.LookupService for DEX swap offers.
type DEXSwapLookupService struct {
	engine *overlay.Engine
}

// NewDEXSwapLookupService creates a DEX swap lookup service.
func NewDEXSwapLookupService(engine *overlay.Engine) *DEXSwapLookupService {
	return &DEXSwapLookupService{engine: engine}
}

// Lookup answers a DEX swap offer query.
func (ls *DEXSwapLookupService) Lookup(queryRaw json.RawMessage) (*overlay.LookupAnswer, error) {
	var q DEXSwapLookupQuery
	if err := json.Unmarshal(queryRaw, &q); err != nil {
		return nil, fmt.Errorf("invalid DEX swap query: %w", err)
	}

	outputs, err := ls.engine.GetOutputsByTopic(DEXSwapTopicName)
	if err != nil {
		return nil, err
	}

	// Return all active offers
	if q.List == "all" {
		return &overlay.LookupAnswer{
			Type:    "output-list",
			Outputs: outputs,
		}, nil
	}

	// Filter by criteria
	var matches []overlay.AdmittedOutput
	for _, out := range outputs {
		var entry DEXSwapEntry
		if err := json.Unmarshal(out.Metadata, &entry); err != nil {
			continue
		}

		// Apply filters (all must match if specified)
		if q.Maker != "" && entry.Maker != q.Maker {
			continue
		}

		if q.OfferingTokenTxid != "" {
			if !containsTokenTxid(entry.Offering, q.OfferingTokenTxid) {
				continue
			}
		}

		if q.RequestingTokenTxid != "" {
			if !containsTokenTxid(entry.Requesting, q.RequestingTokenTxid) {
				continue
			}
		}

		matches = append(matches, out)
	}

	return &overlay.LookupAnswer{
		Type:    "output-list",
		Outputs: matches,
	}, nil
}

// containsTokenTxid checks if a SwapSide JSON contains a specific token txid.
func containsTokenTxid(raw json.RawMessage, txid string) bool {
	// Parse the swap side to check the token field
	var side struct {
		Token *struct {
			Txid string `json:"txid"`
		} `json:"token"`
	}
	if err := json.Unmarshal(raw, &side); err != nil {
		return false
	}
	if side.Token == nil {
		return false
	}
	return strings.EqualFold(side.Token.Txid, txid)
}

// GetDocumentation returns a description of the DEX swap lookup service.
func (ls *DEXSwapLookupService) GetDocumentation() string {
	return "DEX Swap Lookup: Query active peer-to-peer swap offers. Filter by token pair, maker, or list all."
}

// GetMetadata returns machine-readable metadata about the DEX swap lookup service.
func (ls *DEXSwapLookupService) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"service": DEXSwapLookupServiceName,
		"queries": []string{"list", "offering_token_txid", "requesting_token_txid", "maker"},
		"brcs":    []int{22, 24, 79, 87, 92},
	}
}

// Ensure DEXSwapLookupService implements LookupService at compile time.
var _ overlay.LookupService = (*DEXSwapLookupService)(nil)
