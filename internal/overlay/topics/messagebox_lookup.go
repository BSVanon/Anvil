package topics

// MessageBoxLookupServiceName is the BRC-87 canonical name for the
// MessageBox host-advertisement lookup service. Used by the canonical
// lookup at internal/overlay/lookups/messagebox.go.
const MessageBoxLookupServiceName = "ls_messagebox"

// MessageBoxLookupQuery is the query wire shape for the MessageBox
// lookup. Mirrors the canonical MessageBoxQuery
// (MessageBoxStorage.ts:17-20).
type MessageBoxLookupQuery struct {
	// IdentityKey is the hex-encoded identity public key to resolve.
	// Required — canon throws "identityKey query missing"
	// (MessageBoxLookupService.ts:59-61) when it is absent.
	IdentityKey string `json:"identityKey"`
	// Host, given, narrows to adverts with this EXACT host string
	// (MessageBoxStorage.ts:61-78 — a raw Mongo equality filter, not
	// normalised). messaging.HomeResolver does its own normalisation on
	// top of the unfiltered per-identityKey result (the Home Rule); this
	// query-level filter stays a byte-exact match for canon fidelity.
	Host string `json:"host,omitempty"`
}
