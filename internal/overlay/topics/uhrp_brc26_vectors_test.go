package topics

// This file holds focused BRC-26 boundary and mutation coverage not already
// covered by uhrp_brc26_test.go. It stays separate to keep that file within
// the package's per-file size norm.

import (
	"context"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestUHRPBRC26_FreshlyBuiltAdvertAdmitted proves the forSelf=true fix to
// buildUHRPBRC26Script (see that function's comment, uhrp_brc26_test.go)
// actually works: a fresh, non-golden-vector advertisement, built and
// signed entirely in Go, is admitted end to end. Earlier tests did not call
// buildUHRPBRC26Script and then assert a successful
// admit — every existing caller asserted rejection for an unrelated
// reason, so the old forSelf=false's broken key derivation (which made
// the locking key never match what verifyBRC26Linkage independently
// derives) went unnoticed by the suite.
func TestUHRPBRC26_FreshlyBuiltAdvertAdmitted(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x10)
	scriptBytes := buildUHRPBRC26Script(t, w, idPub, hash, "https://fresh.example.com/x", 2000000000, 42)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected a freshly Go-built advert to admit, got %+v", inst)
	}
}

// TestUHRPBRC26_DifferentSignerRejected tests the signature-verification
// half of verifyBRC26Linkage directly — distinct from
// TestUHRPBRC26_WrongSignerRejected (uhrp_brc26_test.go), which leaves
// signing and the identityKey field untouched and instead byte-swaps the
// PushDrop's already-decoded locking key after construction. Here the
// advertisement claims identityKey = alice (field[0] holds alice's
// pubkey), but is actually signed and locked throughout by an unrelated
// wallet (bob) — so the signature never verifies under
// counterparty=alice, the FIRST of verifyBRC26Linkage's two checks,
// which never even reaches the second (locking-key equality).
func TestUHRPBRC26_DifferentSignerRejected(t *testing.T) {
	_, alicePub := uhrpIdentityWallet(t)
	bobWallet, _ := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x11)

	// bobWallet signs and locks; alicePub is only the claimed identityKey
	// field value — the two are unrelated identities.
	scriptBytes := buildUHRPBRC26Script(t, bobWallet, alicePub, hash, "https://example.com/mismatch", 2000000000, 42)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected different-signer advertisement rejected, got %+v", inst)
	}
}

// TestUHRPBRC26_FiveTotalFieldsRejected pins the exact boundary the
// package doc comment (uhrp_brc26.go) describes as a documented
// divergence: canonical's own `fields.length < 5` check runs on the
// PushDrop array BEFORE the signature is popped, so a script with
// exactly 5 total fields (4 content + 1 treated as the signature) passes
// that check, then indexes the now-4-element content array at [4]
// (fileSize) — out of bounds, which canonical's Reader throws over
// `undefined` for. This port instead requires >= 6 total fields up front
// (uhrpBRC26MinFields), so a 5-total-field script is rejected by
// construction rather than by relying on an out-of-bounds access
// happening to throw. TestUHRPBRC26_GoldenVectorAdmitted (6 total
// fields) is the passing side of this exact boundary.
func TestUHRPBRC26_FiveTotalFieldsRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x12)
	// 4 content fields (identityKey, hash, url, expiry — size omitted) +
	// 1 signature = 5 total, one under uhrpBRC26MinFields.
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		[][]byte{idPub, hash, []byte("https://example.com/x"), util.VarInt(2000000000).Bytes()},
		uhrpBRC26Protocol,
		uhrpBRC26KeyID,
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		true,
		true,
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, s.Bytes()), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected exactly-5-total-fields advertisement rejected, got %+v", inst)
	}
}

// TestUHRPBRC26_URLHostAndPortChecks mutation-kills the two new URL
// checks decodeUHRPBRC26 added (empty host, out-of-range port) against URL
// inputs classified by the canonical implementation: `new URL(...)`
// rejects an empty authority outright but still admits the bare
// scheme:opaque form, and rejects a port outside 0-65535.
func TestUHRPBRC26_URLHostAndPortChecks(t *testing.T) {
	cases := []struct {
		name  string
		url   string
		admit bool
	}{
		{"empty authority rejected", "https://", false},
		{"opaque colon form stays admitted (known divergence)", "https:example.com/x", true},
		{"empty host with userinfo+port rejected", "https://user@:443/x", false},
		{"port out of range rejected", "https://example.com:99999/x", false},
		{"ordinary host:port admitted", "https://example.com:8443/x", true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, idPub := uhrpIdentityWallet(t)
			hash := uhrpFreshHash(t, byte(0x20+i))
			scriptBytes := buildUHRPBRC26Script(t, w, idPub, hash, tc.url, 2000000000, 42)

			m := NewUHRPTopicManager()
			inst, err := m.Admit(txWith(t, scriptBytes), nil)
			if err != nil {
				t.Fatalf("Admit: %v", err)
			}
			admitted := inst != nil && len(inst.OutputsToAdmit) == 1
			if admitted != tc.admit {
				t.Fatalf("%q: admitted=%v, want %v (inst=%+v)", tc.url, admitted, tc.admit, inst)
			}
		})
	}
}

// TestUHRPBRC26_HashLengthRejected mutation-kills decodeUHRPBRC26's
// explicit hash-length check with a 31-byte (one short) content-hash
// field — distinct from every existing hash-related test, which all use
// a valid 32-byte hash and tamper its VALUE, not its length.
func TestUHRPBRC26_HashLengthRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	badHash := make([]byte, uhrpBRC26HashLen-1)
	scriptBytes := buildUHRPBRC26Script(t, w, idPub, badHash, "https://example.com/x", 2000000000, 42)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected wrong-length-hash advertisement rejected, got %+v", inst)
	}
}

// TestUHRPBRC26_IdentityKeyLengthRejected mutation-kills decodeUHRPBRC26's
// explicit identityKey-length check (uhrpBRC26IdentityKeyLen's comment)
// with a 65-byte uncompressed encoding of a real, otherwise-valid
// identity key. ec.PublicKeyFromBytes alone parses both forms to the
// same curve point, so without the explicit length check this
// signature would still verify correctly — isolating that the length
// check itself, not an incidental signature failure, is what rejects
// this input.
func TestUHRPBRC26_IdentityKeyLengthRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x30)
	pub, err := ec.PublicKeyFromBytes(idPub)
	if err != nil {
		t.Fatalf("parse identity pub: %v", err)
	}
	uncompressed := pub.Uncompressed()
	if len(uncompressed) == uhrpBRC26IdentityKeyLen {
		t.Fatalf("test construction bug: uncompressed key is already %d bytes", uhrpBRC26IdentityKeyLen)
	}
	scriptBytes := buildUHRPBRC26Script(t, w, uncompressed, hash, "https://example.com/x", 2000000000, 42)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected uncompressed-identityKey advertisement rejected, got %+v", inst)
	}
}

// TestUHRPBRC26_ExpiryAndSizeBoundaries mutation-kills both the
// expiry/size >= 1 guard and the >= 2^53 safe-integer guard
// (uhrpBRC26MaxSafeVarInt's comment), on both operands of each OR'd
// check, plus the admitted side immediately on either side of each
// boundary.
func TestUHRPBRC26_ExpiryAndSizeBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		expiry uint64
		size   uint64
		admit  bool
	}{
		{"expiry zero rejected", 0, 42, false},
		{"size zero rejected", 2000000000, 0, false},
		{"expiry at 2^53 rejected", uhrpBRC26MaxSafeVarInt, 42, false},
		{"size at 2^53 rejected", 2000000000, uhrpBRC26MaxSafeVarInt, false},
		{"expiry exactly 1 admitted", 1, 42, true},
		{"expiry exactly 2^53-1 admitted", uhrpBRC26MaxSafeVarInt - 1, 42, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, idPub := uhrpIdentityWallet(t)
			hash := uhrpFreshHash(t, byte(0x40+i))
			scriptBytes := buildUHRPBRC26Script(t, w, idPub, hash, "https://example.com/x", tc.expiry, tc.size)

			m := NewUHRPTopicManager()
			inst, err := m.Admit(txWith(t, scriptBytes), nil)
			if err != nil {
				t.Fatalf("Admit: %v", err)
			}
			admitted := inst != nil && len(inst.OutputsToAdmit) == 1
			if admitted != tc.admit {
				t.Fatalf("%s: admitted=%v, want %v (inst=%+v)", tc.name, admitted, tc.admit, inst)
			}
		})
	}
}

// TestUHRPBRC26_URLCapRejected mutation-kills uhrpBRC26MaxURLLen's
// upper-bound check with a URL one byte over the cap.
func TestUHRPBRC26_URLCapRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x50)
	prefix := "https://example.com/"
	longURL := prefix + strings.Repeat("a", uhrpBRC26MaxURLLen-len(prefix)+1)
	if len(longURL) != uhrpBRC26MaxURLLen+1 {
		t.Fatalf("test construction bug: longURL length %d, want %d", len(longURL), uhrpBRC26MaxURLLen+1)
	}
	scriptBytes := buildUHRPBRC26Script(t, w, idPub, hash, longURL, 2000000000, 42)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected over-cap URL advertisement rejected, got %+v", inst)
	}
}

// TestUHRPBRC26_URLAtCapAdmitted is the admitted side of the same
// boundary TestUHRPBRC26_URLCapRejected mutation-kills from above: a URL
// exactly at the cap must still be admitted, proving the check is a
// strict "over 4096", not an off-by-one that also rejects the boundary
// value itself.
func TestUHRPBRC26_URLAtCapAdmitted(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x51)
	prefix := "https://example.com/"
	okURL := prefix + strings.Repeat("a", uhrpBRC26MaxURLLen-len(prefix))
	if len(okURL) != uhrpBRC26MaxURLLen {
		t.Fatalf("test construction bug: okURL length %d, want %d", len(okURL), uhrpBRC26MaxURLLen)
	}
	scriptBytes := buildUHRPBRC26Script(t, w, idPub, hash, okURL, 2000000000, 42)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("expected exactly-at-cap URL admitted, got %+v", inst)
	}
}

// TestUHRPBRC26_StrictDERTrailingBytesRejected mutation-kills
// verifyBRC26Linkage's trailing-bytes check. It builds a genuinely valid
// signature over the real content fields, then appends one extra byte
// after the DER encoding before embedding it as the advertisement's
// signature field — asn1.Unmarshal parses the (still well-formed)
// SEQUENCE from the front and reports the extra byte as leftover `rest`,
// exactly the shape go-sdk's own ec.FromDER silently discards. Without
// the trailing-bytes check, this tampered signature would verify
// identically to the untampered one (same leading SEQUENCE, same
// signed data, same key), so this test specifically isolates that check
// — not an incidental signature-verification failure.
func TestUHRPBRC26_StrictDERTrailingBytesRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x60)
	expiry, size := uint64(2000000000), uint64(42)

	content := [][]byte{
		idPub,
		hash,
		[]byte("https://example.com/der"),
		util.VarInt(expiry).Bytes(),
		util.VarInt(size).Bytes(),
	}
	dataToSign := make([]byte, 0)
	for _, f := range content {
		dataToSign = append(dataToSign, f...)
	}
	sigRes, err := w.CreateSignature(context.Background(), wallet.CreateSignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   uhrpBRC26Protocol,
			KeyID:        uhrpBRC26KeyID,
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		},
		Data: dataToSign,
	}, "")
	if err != nil {
		t.Fatalf("CreateSignature: %v", err)
	}
	validDER := sigRes.Signature.Serialize()
	tamperedDER := append(append([]byte{}, validDER...), 0x00) // one trailing byte after the real SEQUENCE

	fieldsWithTamperedSig := append(append([][]byte{}, content...), tamperedDER)
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		fieldsWithTamperedSig,
		uhrpBRC26Protocol,
		uhrpBRC26KeyID,
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		true,  // forSelf
		false, // includeSignature: fieldsWithTamperedSig already carries our own signature field
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, s.Bytes()), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected trailing-bytes DER signature rejected, got %+v", inst)
	}
}
