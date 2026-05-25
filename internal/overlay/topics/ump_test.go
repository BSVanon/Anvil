package topics

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// umpTestWallet returns a canonical CompletedProtoWallet (go-sdk's
// reference test wallet) backed by a fresh private key. Lets PushDrop
// fixture construction use the canonical Lock path, so the produced
// scripts are bit-identical with what a real wallet would emit.
func umpTestWallet(t *testing.T) wallet.Interface {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	return w
}

// buildUMPScript builds a PushDrop UMP locking script with the given
// fields via the canonical pushdrop.PushDrop.Lock path. Tests use this
// to produce realistic fixtures without hand-rolling the script
// encoding.
//
// The protocolID + keyID + counterparty values don't matter for
// admission testing — UMP admission only checks PushDrop shape +
// field semantics, not the signing protocol.
func buildUMPScript(t *testing.T, w wallet.Interface, fields [][]byte) []byte {
	t.Helper()
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		fields,
		wallet.Protocol{
			SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
			Protocol:      "admin user management token",
		},
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		false, // forSelf
		false, // includeSignature: false so test field count matches input exactly (UMP wire format puts 11 protocol fields, no appended signature in canonical UMPLookupService.ts)
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return s.Bytes()
}

// ump11Fields builds a minimal v1/v2 UMP token (11 fields). Field[6] is
// the presentation hash and field[7] is the recovery hash — both must
// be present in the entry produced by ParseUMPOutput.
func ump11Fields(presentationHash, recoveryHash []byte) [][]byte {
	return [][]byte{
		{0x01},          // 0: passwordSalt (placeholder)
		{0x02},          // 1: passwordPresentationPrimary (placeholder)
		{0x03},          // 2: passwordRecoveryPrimary (placeholder)
		{0x04},          // 3: presentationRecoveryPrimary (placeholder)
		{0x05},          // 4: passwordPrimaryPrivileged (placeholder)
		{0x06},          // 5: presentationRecoveryPrivileged (placeholder)
		presentationHash, // 6: presentationHash (clear, lookup key)
		recoveryHash,    // 7: recoveryHash (clear, lookup key)
		{0x09},          // 8: presentationKeyEncrypted (placeholder)
		{0x0a},          // 9: passwordKeyEncrypted (placeholder)
		{0x0b},          // 10: recoveryKeyEncrypted (placeholder)
	}
}

// ump15FieldsV3 extends ump11Fields with v3 detection: profilesEncrypted
// at index 11 (intentionally >1 byte so v3 detection skips it and lands
// on the version byte at index 12 — matches the "hasV3AtIndex12" branch
// of UMPTopicManager.ts:21).
func ump15FieldsV3(presentationHash, recoveryHash []byte, kdfAlg string, iterations uint32) [][]byte {
	fields := ump11Fields(presentationHash, recoveryHash)
	fields = append(fields,
		[]byte{0x0c, 0x0d, 0x0e},     // 11: profilesEncrypted (>1 byte to skip v3-at-11 detection)
		[]byte{UMPVersionV3},          // 12: umpVersion (single byte = 3)
		[]byte(kdfAlg),                // 13: kdfAlgorithm
		[]byte(`{"iterations":3}`),     // 14: kdfParams (placeholder iterations=3)
	)
	_ = iterations // single-iteration value for now; specific counts would need a real JSON build
	_ = strings.Repeat
	return fields
}

// hash32 produces a 32-byte sentinel from a seed byte. Convenient for
// readable test fixtures (every test wants a unique presentationHash).
func hash32(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed
	}
	return out
}

// TestParseUMPOutput_V1V2Token pins the happy path: an 11-field
// PushDrop output PushDrop-decodes cleanly + ParseUMPOutput yields
// the expected presentationHash + recoveryHash hex with UMPVersion=0
// (no v3 detection).
func TestParseUMPOutput_V1V2Token(t *testing.T) {
	w := umpTestWallet(t)
	presH := hash32(0xaa)
	recH := hash32(0xbb)
	scriptBytes := buildUMPScript(t, w, ump11Fields(presH, recH))

	entry, err := ParseUMPOutput(scriptBytes)
	if err != nil {
		t.Fatalf("ParseUMPOutput: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.PresentationHash != hex.EncodeToString(presH) {
		t.Fatalf("PresentationHash mismatch: want %s, got %s",
			hex.EncodeToString(presH), entry.PresentationHash)
	}
	if entry.RecoveryHash != hex.EncodeToString(recH) {
		t.Fatalf("RecoveryHash mismatch: want %s, got %s",
			hex.EncodeToString(recH), entry.RecoveryHash)
	}
	if entry.UMPVersion != 0 {
		t.Fatalf("expected v1/v2 token (UMPVersion=0), got %d", entry.UMPVersion)
	}
}

// TestParseUMPOutput_V3Token verifies v3 detection works and populates
// the kdfAlgorithm + kdfIterations fields. The v3 layout used here has
// the version byte at index 12 (with profilesEncrypted at 11).
func TestParseUMPOutput_V3Token(t *testing.T) {
	w := umpTestWallet(t)
	presH := hash32(0xa1)
	recH := hash32(0xb1)
	scriptBytes := buildUMPScript(t, w, ump15FieldsV3(presH, recH, UMPKDFArgon2id, 3))

	entry, err := ParseUMPOutput(scriptBytes)
	if err != nil {
		t.Fatalf("ParseUMPOutput v3: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil entry")
	}
	if entry.UMPVersion != UMPVersionV3 {
		t.Fatalf("expected UMPVersion=%d, got %d", UMPVersionV3, entry.UMPVersion)
	}
	if entry.KDFAlgorithm != UMPKDFArgon2id {
		t.Fatalf("expected KDFAlgorithm=%s, got %q", UMPKDFArgon2id, entry.KDFAlgorithm)
	}
	if entry.KDFIterations != 3 {
		t.Fatalf("expected KDFIterations=3, got %d", entry.KDFIterations)
	}
}

// TestParseUMPOutput_V3UnsupportedKDFAlgRejected confirms the canonical
// UMPTopicManager.ts:38-39 invariant: anything other than argon2id or
// pbkdf2-sha512 in the kdfAlgorithm field must be rejected.
func TestParseUMPOutput_V3UnsupportedKDFAlgRejected(t *testing.T) {
	w := umpTestWallet(t)
	scriptBytes := buildUMPScript(t, w, ump15FieldsV3(hash32(0xc1), hash32(0xc2), "rot13", 3))
	entry, err := ParseUMPOutput(scriptBytes)
	if err == nil {
		t.Fatalf("expected error for unsupported KDF algorithm, got entry=%+v", entry)
	}
	if entry != nil {
		t.Fatalf("expected nil entry on rejected token, got %+v", entry)
	}
}

// TestParseUMPOutput_TooFewFieldsRejected verifies the UMPMinFields=11
// guard. A 10-field PushDrop output is not a valid UMP token.
func TestParseUMPOutput_TooFewFieldsRejected(t *testing.T) {
	w := umpTestWallet(t)
	short := make([][]byte, 10)
	for i := range short {
		short[i] = []byte{byte(i)}
	}
	scriptBytes := buildUMPScript(t, w, short)
	entry, err := ParseUMPOutput(scriptBytes)
	if err != nil {
		t.Fatalf("ParseUMPOutput short: %v", err)
	}
	if entry != nil {
		t.Fatalf("expected nil entry for 10-field token, got %+v", entry)
	}
}

// TestParseUMPOutput_NonPushDropScriptIgnored confirms that a script
// which doesn't decode as PushDrop returns (nil, nil) — i.e. neither a
// match nor an error. Matches the TS impl's behavior of silently
// skipping outputs that aren't UMP-shaped.
func TestParseUMPOutput_NonPushDropScriptIgnored(t *testing.T) {
	// A trivial OP_1 script. Not a PushDrop output.
	entry, err := ParseUMPOutput([]byte{0x51})
	if err != nil {
		t.Fatalf("non-PushDrop script returned error: %v", err)
	}
	if entry != nil {
		t.Fatalf("non-PushDrop script returned entry: %+v", entry)
	}
}

// TestParseUMPOutput_EmptyScriptRejected pins the nil-safety guard.
func TestParseUMPOutput_EmptyScriptRejected(t *testing.T) {
	entry, err := ParseUMPOutput(nil)
	if err != nil || entry != nil {
		t.Fatalf("expected (nil, nil) for empty script, got (%+v, %v)", entry, err)
	}
	entry, err = ParseUMPOutput([]byte{})
	if err != nil || entry != nil {
		t.Fatalf("expected (nil, nil) for zero-length script, got (%+v, %v)", entry, err)
	}
}
