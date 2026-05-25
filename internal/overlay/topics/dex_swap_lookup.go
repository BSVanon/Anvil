package topics

// DEXSwapLookupServiceName is the BRC-87 standard name for the DEX
// swap lookup service. Used by lookups.NewDEXSwapLookupService and the
// legacy compat shim.
const DEXSwapLookupServiceName = "ls_dex_swap"

// DEXSwapLookupQuery is the query wire shape for the DEX swap lookup
// service. Decoded by both lookups.DEXSwapLookupService and the legacy
// shim's /overlay/query handler.
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

// W-7 (2026-05-16): the legacy in-process DEXSwapLookupService struct +
// NewDEXSwapLookupService constructor + Lookup/GetDocumentation/
// GetMetadata methods + the internal containsTokenTxid helper were
// removed here. The replacement is lookups.NewDEXSwapLookupService at
// internal/overlay/lookups/dex_swap.go, which implements the canonical
// engine.LookupService against an event-driven local index. The
// canonical lookup re-implements containsTokenTxid locally rather
// than re-importing from this package.
