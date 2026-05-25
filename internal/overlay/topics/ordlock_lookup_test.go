package topics

import (
	"encoding/hex"
	"testing"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	"github.com/bsv-blockchain/go-sdk/script"
)

// W-7 (2026-05-16): every other test in this file targeted the
// removed legacy OrdLockLookupService / matchesOrdLockQuery /
// normalizeLimitOffset / lifecycle paths. Equivalent coverage lives
// in internal/overlay/lookups/ordlock_test.go for the canonical
// service. The TestNormalizeCancelFilter sub-tests are kept here
// because NormalizeCancelFilter is the shared helper that both the
// canonical OrdLock and OrdLock-buy lookups still import directly.

func TestNormalizeCancelFilter(t *testing.T) {
	t.Run("empty input → empty filter", func(t *testing.T) {
		got, err := NormalizeCancelFilter("")
		if err != nil || got != "" {
			t.Errorf("got (%q, %v), want (\"\", nil)", got, err)
		}
	})
	t.Run("valid mainnet address → 20-byte pkh hex", func(t *testing.T) {
		// Derive a known address from a known pkh and round-trip it.
		pkh, _ := hex.DecodeString("28672b084a32711ee267c1e61f49771784620e9f")
		addr, _ := script.NewAddressFromPublicKeyHash(pkh, true)
		got, err := NormalizeCancelFilter(addr.AddressString)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "28672b084a32711ee267c1e61f49771784620e9f" {
			t.Errorf("got pkh hex %q, want %q", got, "28672b084a32711ee267c1e61f49771784620e9f")
		}
	})
	t.Run("garbage input → error", func(t *testing.T) {
		if _, err := NormalizeCancelFilter("not-an-address"); err == nil {
			t.Error("expected error on garbage address")
		}
	})
	t.Run("testnet address → error (mainnet-only surface)", func(t *testing.T) {
		// Build a testnet P2PKH (version 0x6f) for a known pkh and confirm
		// the lookup rejects it instead of silently matching on the bare pkh.
		pkh, _ := hex.DecodeString("28672b084a32711ee267c1e61f49771784620e9f")
		testnetAddr, _ := script.NewAddressFromPublicKeyHash(pkh, false)
		_, err := NormalizeCancelFilter(testnetAddr.AddressString)
		if err == nil {
			t.Errorf("testnet cancelAddress %q must be rejected on this mainnet-only surface", testnetAddr.AddressString)
		}
	})
	t.Run("mainnet-looking address with bad checksum → error", func(t *testing.T) {
		// Take a valid mainnet address, decode it, corrupt the trailing
		// checksum byte, re-encode, and confirm the filter rejects it.
		// Without checksum validation a payload like this would pass the
		// length + version checks and silently match listings by bare pkh.
		pkh, _ := hex.DecodeString("28672b084a32711ee267c1e61f49771784620e9f")
		good, _ := script.NewAddressFromPublicKeyHash(pkh, true)
		raw, err := base58.Decode(good.AddressString)
		if err != nil {
			t.Fatalf("decode good address: %v", err)
		}
		raw[len(raw)-1] ^= 0xff // flip last checksum byte
		corrupted := base58.Encode(raw)
		if _, err := NormalizeCancelFilter(corrupted); err == nil {
			t.Errorf("bad-checksum address %q must be rejected", corrupted)
		}
	})
}
