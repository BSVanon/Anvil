package topics

// OrdLockBuyLookupServiceName is the BRC-87 lookup service name for
// OrdLock buy-side vaults. Used by lookups.NewOrdLockBuyLookupService
// and the legacy compat shim.
const OrdLockBuyLookupServiceName = "ls_ordlock_buy_vaults"

// OrdLockBuyQuery is the wire query shape for ls_ordlock_buy_vaults.
// Decoded by both lookups.OrdLockBuyLookupService and the legacy
// shim's /overlay/query handler.
type OrdLockBuyQuery struct {
	List          string `json:"list,omitempty"`          // "all" returns everything
	TokenId       string `json:"tokenId,omitempty"`       // filter to single BSV-21
	Tick          string `json:"tick,omitempty"`          // filter to BSV-20 (case-insensitive)
	CancelAddress string `json:"cancelAddress,omitempty"` // filter by buyer's cancel-key (base58check)
	Outpoint      string `json:"outpoint,omitempty"`      // filter to a single outpoint
	Limit         int    `json:"limit,omitempty"`         // default 100, max 500
	Offset        int    `json:"offset,omitempty"`        // default 0
}

// W-7 (2026-05-16): the legacy in-process OrdLockBuyLookupService
// struct + NewOrdLockBuyLookupService constructor + Lookup/
// GetDocumentation/GetMetadata methods + matchesOrdLockBuyQuery +
// normalizeOrdLockBuyLimitOffset internal helpers were removed here.
// The replacement is lookups.NewOrdLockBuyLookupService at
// internal/overlay/lookups/ordlock_buy.go, which uses
// topics.NormalizeCancelFilter directly for the cancel-address check.
