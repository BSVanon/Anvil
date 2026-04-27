package topics

import (
	"encoding/hex"
	"strings"
	"testing"
)

// liveVaultScriptHex is the locking script of the buy vault created on
// mainnet 2026-04-27 by BSVanon as part of the B-buy.7 click-test
// (tx d0496e6fac47dab038706afd5a0e1676372c09a9a620359cdc528595cecc8f6e:0,
// 1500 sats locked). Used as ground truth that the structural parser
// matches a real Anvil-Swap-built vault byte-for-byte. If the
// canonical TS builder ever drifts, this test catches it.
const liveVaultScriptHex = "76009c63755279ab547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad6908e803000000000000041976a9147e7b0288ac7e7e4cb30100000000000000aa0063036f726451126170706c69636174696f6e2f6273762d3230004c737b2270223a226273762d3230222c226f70223a227472616e73666572222c22616d74223a223530222c226964223a22336335646536313362333661616461643531646163333461303437326138373861343263343132356234343835303438313039323761333737643531363263345f30227d6876a9148dd8631a9c2285f523da15a1b8d874a3fda00eea88ac7c7e7c7eaa7c820128947f7701207f758767519d5279ab557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad69537a210312e3db769544cf899b8c0961594f6c474f1f4166ad0c1b47c55413e9f2321c54ad7c041976a9147e147d8cf389745e933753d26b970cb29437c4605a950288ac7e7e7c7eaa7c820128947f7701207f758768"

func TestParseOrdLockBuyScript_LiveVault(t *testing.T) {
	script, err := hex.DecodeString(liveVaultScriptHex)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	entry := parseOrdLockBuyScript(script)
	if entry == nil {
		t.Fatal("parser returned nil for known-good live vault script")
	}

	if entry.PriceSats != 1000 {
		t.Errorf("priceSats: got %d, want 1000", entry.PriceSats)
	}
	if got := strings.ToLower(entry.BuyerPubKeyHex); got != "0312e3db769544cf899b8c0961594f6c474f1f4166ad0c1b47c55413e9f2321c54" {
		t.Errorf("buyerPubKey: got %s", got)
	}
	if got := strings.ToLower(entry.CancelPkhHex); len(got) != 40 {
		t.Errorf("cancelPkh: got len %d, want 40 hex chars", len(got))
	}
	if entry.Protocol != "bsv-21" {
		t.Errorf("protocol: got %q, want bsv-21", entry.Protocol)
	}
	if entry.TokenId != "3c5de613b36aadad51dac34a0472a878a42c4125b448504810927a377d5162c4_0" {
		t.Errorf("tokenId: got %q", entry.TokenId)
	}
	if entry.RequestedAmount != "50" {
		t.Errorf("requestedAmount: got %q, want 50", entry.RequestedAmount)
	}
	if entry.ExpectedOutput0Hex == "" {
		t.Error("expectedOutput0Hex empty")
	}
	if got := strings.ToLower(entry.ScriptHex); got != strings.ToLower(liveVaultScriptHex) {
		t.Errorf("scriptHex round-trip mismatch: got %d chars, want %d", len(got), len(liveVaultScriptHex))
	}
}

func TestParseOrdLockBuyScript_RejectsTooShort(t *testing.T) {
	if entry := parseOrdLockBuyScript([]byte{0x76, 0x00, 0x9c}); entry != nil {
		t.Error("parser accepted 3-byte script")
	}
}

func TestParseOrdLockBuyScript_RejectsBadPrefix(t *testing.T) {
	script, _ := hex.DecodeString(liveVaultScriptHex)
	script[0] = 0xff // corrupt first byte of prefix
	if entry := parseOrdLockBuyScript(script); entry != nil {
		t.Error("parser accepted script with corrupted prefix")
	}
}

func TestParseOrdLockBuyScript_RejectsBadSuffix(t *testing.T) {
	script, _ := hex.DecodeString(liveVaultScriptHex)
	script[len(script)-1] = 0xff // corrupt last byte of suffix
	if entry := parseOrdLockBuyScript(script); entry != nil {
		t.Error("parser accepted script with corrupted suffix")
	}
}

func TestParseOrdLockBuyScript_RejectsBadP2PKHConstant(t *testing.T) {
	script, _ := hex.DecodeString(liveVaultScriptHex)
	// The first p2pkhVarintPrefix push begins at byte 46+10 = 56 (after the 8-byte priceSatsLE push).
	// Push opcode 0x04 at byte 56; payload at byte 57 = first byte of "1976a914". Corrupt it.
	script[57] = 0xff
	if entry := parseOrdLockBuyScript(script); entry != nil {
		t.Error("parser accepted script with corrupted p2pkhVarintPrefix constant")
	}
}

func TestParseOrdLockBuyScript_RejectsPureSellListing(t *testing.T) {
	// A canonical SELL OrdLock listing should NOT match the BUY parser.
	// Construct a minimum-shape OP_FALSE OP_IF "ord" OP_1 push payload OP_ENDIF
	// + OLOCK_PREFIX_HEX + cancelPkh push + payOutput push + OLOCK_SUFFIX_HEX.
	// Trivial test: take any script that doesn't start with the OrdLockBuy
	// prefix bytes and confirm we reject.
	bogus := append([]byte{0x00, 0x63, 0x03, 0x6f, 0x72, 0x64, 0x51}, make([]byte, 800)...)
	if entry := parseOrdLockBuyScript(bogus); entry != nil {
		t.Error("parser accepted a non-OrdLockBuy script")
	}
}

func TestDecodePriceSatsLE(t *testing.T) {
	cases := []struct {
		name    string
		hex     string
		want    int64
		wantErr bool
	}{
		{"1000 sats", "e803000000000000", 1000, false},
		{"1 sat", "0100000000000000", 1, false},
		{"1 BSV", "00e1f50500000000", 100_000_000, false},
		{"zero rejected", "0000000000000000", 0, true},
		{"wrong length", "e80300000000", 0, true},
		{"bad hex", "zz", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodePriceSatsLE(c.hex)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestArtifactSelfConsistency(t *testing.T) {
	// Sanity: every slot offset in the artifact template hosts a 0x00
	// placeholder and slots are sorted ascending. This is checked at
	// init() too; the test here is the regression guard.
	for i, s := range ordLockBuySlots {
		if s.byteOffset >= len(olockBuyArtifactBytes) {
			t.Fatalf("slot %d byteOffset %d out of range", i, s.byteOffset)
		}
		if olockBuyArtifactBytes[s.byteOffset] != 0x00 {
			t.Errorf("slot %d at byteOffset %d not a placeholder (got 0x%02x)", i, s.byteOffset, olockBuyArtifactBytes[s.byteOffset])
		}
		if i > 0 && s.byteOffset <= ordLockBuySlots[i-1].byteOffset {
			t.Errorf("slots out of order at %d", i)
		}
	}
	if len(olockBuyPrefixBytes) != ordLockBuySlots[0].byteOffset {
		t.Errorf("prefix length mismatch")
	}
}
