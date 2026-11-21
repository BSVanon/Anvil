package topics

// UHRPLookupServiceName is the BRC-87 standard name for the UHRP
// lookup service. Used by the canonical lookup service at
// internal/overlay/lookups/uhrp.go and by the legacy compat shim.
const UHRPLookupServiceName = "ls_uhrp"

// UHRPLookupQuery is the query wire shape for the UHRP lookup service.
// Decoded by both the canonical lookup (lookups.UHRPLookupService) and
// the legacy shim's /overlay/query handler so callers see identical
// behaviour regardless of which route they hit.
//
// Outpoint, HostIdentityKey
// and ExpiryTime port canonical UHRPLookupService.ts's query keys
// (overlays/topics uhrp/UHRPLookupService.ts, method lookup()). Outpoint
// is a direct single-record lookup, independent of every other key —
// canonical's lookup() returns on that path before even inspecting the
// rest of the query object, so Anvil's Lookup does the same. Absent an
// Outpoint, canonical AND-combines every key supplied (its
// `records.find(query)` is Mongo's implicit multi-field exact match):
// HostIdentityKey and ExpiryTime narrow whatever base set ContentHash /
// UhrpUrl / List selects, or — supplied alone, with no hash and no list —
// scan every entry the way List:"all" does. List itself is an Anvil-only
// extension; canonical has no list-everything query.
type UHRPLookupQuery struct {
	// ContentHash resolves a specific file by its SHA-256 hash (hex).
	ContentHash string `json:"content_hash,omitempty"`
	// UhrpUrl resolves a file by its canonical BRC-26 UHRP URL
	// ("uhrp://..." / "web+uhrp://..."). Anvil decodes it to the content
	// hash via go-sdk storage.GetHashFromURL, so canonical @bsv/sdk
	// StorageDownloader clients — which resolve by uhrpUrl, not raw hash —
	// work without pre-decoding. Explicit ContentHash wins if both are
	// set. This is the one query shape that answers with ONLY BRC-26
	// records: StorageDownloader.resolve() PushDrop-decodes every
	// returned output with no try/catch, so a legacy OP_RETURN record
	// (not PushDrop-shaped at all) would make it throw — see
	// lookups.UHRPLookupService.Lookup.
	UhrpUrl string `json:"uhrpUrl,omitempty"`
	// Outpoint is canonical's direct single-record query key:
	// "<txid-hex>.<outputIndex>" (dot-separated, matching the canonical
	// wire format exactly — Anvil's own internal outpoint strings
	// elsewhere use "_", but this field is what an external canonical
	// client sends). When set, every other key on this struct is ignored.
	Outpoint string `json:"outpoint,omitempty"`
	// HostIdentityKey is Anvil's filter on an advertisement's identity key
	// (hex), matched case-insensitively. AND-combines with every other key
	// supplied, per the struct doc comment above. Deliberate divergence
	// from canonical, which matches case-sensitively against lowercase hex
	// — see uhrpQueryFilter.matches's doc comment for the exact canonical
	// citation.
	HostIdentityKey string `json:"hostIdentityKey,omitempty"`
	// ExpiryTime is canonical's exact-match filter on an advertisement's
	// absolute Unix-seconds expiry — a strict equality, never a range (see
	// uhrpQueryFilter.matches's doc comment for the canonical citation).
	// AND-combines the same way HostIdentityKey does. Zero means "not
	// supplied": a stored advertisement's expiry is always >= 1 (admission
	// enforces it), so zero can never be a real value worth querying for.
	ExpiryTime int64 `json:"expiryTime,omitempty"`
	// List returns all UHRP entries. Values: "all", "hashes". Anvil-only.
	List string `json:"list,omitempty"`
}

// The legacy in-process UHRP lookup implementation was removed. The
// replacement is
// lookups.NewUHRPLookupService at internal/overlay/lookups/uhrp.go,
// which implements the canonical engine.LookupService against an
// event-driven local index. The constants + query types stay because
// they're part of the source-compat surface the canonical lookup +
// legacy shim share.
