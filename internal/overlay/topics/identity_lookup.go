package topics

// IdentityLookupServiceName is the BRC-87 canonical name for the
// identity lookup service. Used by the canonical lookup at
// internal/overlay/lookups/identity.go and by the legacy compat shim.
const IdentityLookupServiceName = "ls_identity"

// IdentityLookupQuery is the query wire shape. Mirrors the canonical
// IdentityLookupService.ts lookup contract: callers select by
// identityKey (hex compressed pubkey), by certifier (Anvil extension),
// by outpoint, or by attributes (subject fields like {handle, domain}
// for paymail resolution).
//
// v3.0.0 implementation status:
//
//   - IdentityKey:   fully supported (output-list / BEEF answer)
//   - CertifierKey:  fully supported (output-list / BEEF answer)
//   - Outpoint:      fully supported (output-list / BEEF answer)
//   - Attributes:    deferred to W-11 — returns Freeform answer
//                    `{deferred:true, use:"identityKey"}` so wallets
//                    fall back to the two-step paymail protocol
//                    (bsvalias HTTP gateway → identityKey → identityKey
//                    lookup). See docs/internal/SENDBSV_USERS_TOPIC_REQUEST.md
//                    § "Identity attributes deferral (W-11)" for the
//                    resolution plan + the two options for getting
//                    there in v3.1.0.
type IdentityLookupQuery struct {
	// IdentityKey resolves a cert by the subject's hex-encoded
	// compressed pubkey. Primary lookup pattern.
	IdentityKey string `json:"identityKey,omitempty"`
	// CertifierKey scopes the query to a specific certifier. Combined
	// with IdentityKey it returns the cert from that certifier for
	// that subject. Anvil extension beyond the canonical TS contract.
	CertifierKey string `json:"certifierKey,omitempty"`
	// Outpoint is a "txid.vout" string for republish / health checks.
	Outpoint string `json:"outpoint,omitempty"`
	// Attributes is the wallet-facing "find me by handle" query. In
	// v3.0.0 this returns the deferred-flag Freeform answer described
	// above. Wallets are expected to use the two-step paymail protocol
	// (bsvalias HTTP gateway + identityKey lookup) until W-11 lands.
	Attributes map[string]string `json:"attributes,omitempty"`
}
