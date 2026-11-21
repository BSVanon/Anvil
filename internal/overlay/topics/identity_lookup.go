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
//   - Attributes:    returns a deferred Freeform answer
//     `{deferred:true, use:"identityKey", since:"v3.0.0"}` so wallets
//     fall back to the two-step paymail protocol
//     (bsvalias HTTP gateway → identityKey → identityKey
//     lookup) until attribute decryption is available.
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
	// (bsvalias HTTP gateway + identityKey lookup) until attribute decryption
	// is available.
	Attributes map[string]string `json:"attributes,omitempty"`
}
