package topics

// UMPLookupServiceName is the BRC-87 canonical name for the UMP
// lookup service. Used by the canonical lookup service at
// internal/overlay/lookups/ump.go and by the legacy compat shim.
const UMPLookupServiceName = "ls_users"

// UMPLookupQuery is the query wire shape for the UMP lookup. Mirrors
// UMPLookupService.ts:64-77 — callers select exactly one of
// PresentationHash / RecoveryHash / Outpoint.
//
// The TS implementation accepts only one filter at a time and returns
// the single most-recently-inserted record. Anvil follows the same
// semantic (single record per query) but exposes the parsed query
// shape via JSON so the legacy compat shim and canonical lookup share
// the same decode path.
type UMPLookupQuery struct {
	// PresentationHash resolves a returning-user same-passkey
	// rehydrate. Hex-encoded SHA-256 hash, lowercase.
	PresentationHash string `json:"presentationHash,omitempty"`
	// RecoveryHash resolves a lost-passkey + recovery-key restore.
	// Hex-encoded SHA-256 hash, lowercase.
	RecoveryHash string `json:"recoveryHash,omitempty"`
	// Outpoint is a "txid.vout" string for republish / health check
	// lookups.
	Outpoint string `json:"outpoint,omitempty"`
}
