package topics

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
)

// OrdLockLookupServiceName is the BRC-87 lookup service name. Used by
// lookups.NewOrdLockLookupService and the legacy compat shim.
const OrdLockLookupServiceName = "ls_ordlock_listings"

// OrdLockQuery is the wire query shape for ls_ordlock_listings.
// Field naming follows N2/N3 in docs/internal/ORDLOCK_TOPIC_REQUEST.md.
// Decoded by both lookups.OrdLockLookupService and the legacy shim's
// /overlay/query handler.
type OrdLockQuery struct {
	List          string `json:"list,omitempty"`          // "all" returns everything
	TokenId       string `json:"tokenId,omitempty"`       // filter to single BSV-21
	Tick          string `json:"tick,omitempty"`          // filter to BSV-20 (case-insensitive)
	CancelAddress string `json:"cancelAddress,omitempty"` // filter by seller's cancel-key (base58check)
	Limit         int    `json:"limit,omitempty"`         // default 100, max 500
	Offset        int    `json:"offset,omitempty"`        // default 0
}

// W-7 (2026-05-16): the legacy in-process OrdLockLookupService struct
// + NewOrdLockLookupService constructor + Lookup/GetDocumentation/
// GetMetadata methods + matchesOrdLockQuery + normalizeLimitOffset
// internal helpers were removed here. The replacement is
// lookups.NewOrdLockLookupService at internal/overlay/lookups/ordlock.go,
// which implements the canonical engine.LookupService with the same
// filter semantics. NormalizeCancelFilter is KEPT (exported) because
// canonical lookups for both OrdLock and OrdLock-buy import it directly
// — see internal/overlay/lookups/ordlock.go:166 +
// internal/overlay/lookups/ordlock_buy.go:155.

// NormalizeCancelFilter converts a mainnet base58check P2PKH address to a
// 20-byte pkh hex string. Empty input → empty filter (no-op). Invalid input
// (testnet/regtest prefixes, wrong length, bad SHA256d checksum, or any
// non-base58 characters) is a query error so callers learn their request is
// malformed rather than silently getting empty results.
//
// Three checks, all required:
//  1. Length: 25 bytes (1 version + 20 pkh + 4 checksum).
//  2. Version: 0x00 (mainnet P2PKH only). 0x6f (testnet) is rejected because
//     this surface is mainnet-only and a testnet address would otherwise
//     silently match a mainnet listing on the bare 20-byte pkh.
//  3. Checksum: SHA256d of the first 21 bytes must equal the trailing 4
//     bytes. Without this a payload that just happens to start with 0x00
//     and be 25 bytes long would pass validation.
//
// Decoding raw rather than via script.NewAddressFromString because that helper
// accepts both 0x00 and 0x6f prefixes; we want strict mainnet-only rejection.
func NormalizeCancelFilter(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", nil
	}
	decoded, err := base58.Decode(addr)
	if err != nil {
		return "", fmt.Errorf("invalid cancelAddress %q: %w", addr, err)
	}
	if len(decoded) != 25 {
		return "", fmt.Errorf("cancelAddress %q is not a 25-byte base58check payload", addr)
	}
	if decoded[0] != 0x00 {
		return "", fmt.Errorf("cancelAddress %q is not a mainnet P2PKH (version=0x%02x)", addr, decoded[0])
	}
	want := crypto.Sha256d(decoded[:21])[:4]
	if !bytes.Equal(want, decoded[21:25]) {
		return "", fmt.Errorf("cancelAddress %q has an invalid base58check checksum", addr)
	}
	pkh := decoded[1:21]
	return strings.ToLower(hex.EncodeToString(pkh)), nil
}
