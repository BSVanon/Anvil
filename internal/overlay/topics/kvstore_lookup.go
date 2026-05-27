package topics

import "encoding/json"

// KVStoreLookupServiceName is the BRC-87 canonical name for the KVStore
// lookup service. Used by the canonical lookup at
// internal/overlay/lookups/kvstore.go.
const KVStoreLookupServiceName = "ls_kvstore"

// KVStoreLookupQuery is the query wire shape for the KVStore lookup.
// Mirrors the canonical KVStoreQuery in ts-stack kvstore/types.ts and
// the BRC-35 §3.5 query schema. Callers must supply at least one
// selector (key, controller, protocolID, or tags); the remaining
// selectors AND-narrow the result set.
type KVStoreLookupQuery struct {
	// Key matches the UTF-8 KVStore key exactly.
	Key string `json:"key,omitempty"`
	// Controller matches the hex-encoded controller identity pubkey.
	Controller string `json:"controller,omitempty"`
	// ProtocolID is the canonical [securityLevel, name] array (a
	// WalletProtocol). Compared against the stored protocolID via its
	// canonical JSON form, matching the canonical findWithFilters
	// JSON.stringify(protocolID) comparison.
	ProtocolID json.RawMessage `json:"protocolID,omitempty"`
	// Tags filters by the token's tags. Combined with TagQueryMode.
	Tags []string `json:"tags,omitempty"`
	// TagQueryMode is "all" (record must contain every query tag,
	// default) or "any" (record must contain at least one).
	TagQueryMode string `json:"tagQueryMode,omitempty"`
	// Limit caps the number of returned references (canonical default
	// 50). Skip offsets into the sorted result set.
	Limit int `json:"limit,omitempty"`
	Skip  int `json:"skip,omitempty"`
	// SortOrder is "desc" (most-recent first, default) or "asc", ordering
	// by admission time (the LevelDB analogue of the canonical createdAt
	// sort).
	SortOrder string `json:"sortOrder,omitempty"`
}
