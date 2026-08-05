package topics

// UHRPLookupServiceName is the BRC-87 standard name for the UHRP
// lookup service. Used by the canonical lookup service at
// internal/overlay/lookups/uhrp.go and by the legacy compat shim.
const UHRPLookupServiceName = "ls_uhrp"

// UHRPLookupQuery is the query wire shape for the UHRP lookup service.
// Decoded by both the canonical lookup (lookups.UHRPLookupService) and
// the legacy shim's /overlay/query handler so callers see identical
// behaviour regardless of which route they hit.
type UHRPLookupQuery struct {
	// ContentHash resolves a specific file by its SHA-256 hash (hex).
	ContentHash string `json:"content_hash,omitempty"`
	// UhrpUrl resolves a file by its canonical BRC-26 UHRP URL
	// ("uhrp://..." / "web+uhrp://..."). Anvil decodes it to the content
	// hash via go-sdk storage.GetHashFromURL, so canonical @bsv/sdk
	// StorageDownloader clients — which resolve by uhrpUrl, not raw hash —
	// work without pre-decoding. Explicit ContentHash wins if both are set.
	UhrpUrl string `json:"uhrpUrl,omitempty"`
	// List returns all UHRP entries. Values: "all", "hashes"
	List string `json:"list,omitempty"`
}

// W-7 (2026-05-16): the legacy in-process UHRPLookupService struct +
// NewUHRPLookupService constructor + Lookup/GetDocumentation/GetMetadata
// methods were removed here. The replacement is
// lookups.NewUHRPLookupService at internal/overlay/lookups/uhrp.go,
// which implements the canonical engine.LookupService against an
// event-driven local index. The constants + query types stay because
// they're part of the source-compat surface the canonical lookup +
// legacy shim share.
