package topics

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// --- golden vector -----------------------------------------------------
//
// A shared cross-team BRC-26/BRC-42 parity fixture: a UHRP advertisement
// signed by a known test private key. Pure cryptographic test material
// (private key, hashes, DER signature bytes) — not derived from, and not
// pointing at, any real deployment. Field layout and byte offsets were
// confirmed against go-sdk's own pushdrop.Decode before use here: 6
// PushDrop fields (identityKey, sha256, url, varint expiry, varint size,
// signature), content-hash field at script byte offset 70.
const (
	uhrpGoldenIdentityPub      = "026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3"
	uhrpGoldenContentHash      = "3b14896967f5498654c1864225b8ad9460d0d22af9bd339ac6ea6907f09293bd"
	uhrpGoldenURL              = "https://anvil.example.com/content/abababababababababababababababababababababababababababababababab_0"
	uhrpGoldenExpiry           = int64(2000000000)
	uhrpGoldenLockingScriptHex = "21025ede965034125c2533610740d5d1c3db9555d196247aa1fbcdf34fe2723c1436ac" +
		"21026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3" +
		"203b14896967f5498654c1864225b8ad9460d0d22af9bd339ac6ea6907f09293bd" +
		"4c6468747470733a2f2f616e76696c2e6578616d706c652e636f6d2f636f6e74656e742f" +
		"61626162616261626162616261626162616261626162616261626162616261626162" +
		"6162616261626162616261626162616261626162616261626162616261625f30" +
		"05fe0094357703fdd204" +
		"473045022100b5cf1d72b0fd80dded03d56da620a6a937ecb69854ec7a406a005a077ba1c8ed02201ad980e4b79b1f965c1420947ed3b9353e264f588c46733d332c749ee07d661b" +
		"6d6d6d"
)

// uhrpGoldenScriptBytes decodes the golden vector's locking script.
func uhrpGoldenScriptBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(uhrpGoldenLockingScriptHex)
	if err != nil {
		t.Fatalf("decode golden script hex: %v", err)
	}
	return b
}

// --- test helpers --------------------------------------------------------

// uhrpIdentityWallet returns a fresh CompletedProtoWallet plus its identity
// (root) public key's compressed bytes — the value that goes in a BRC-26
// token's field[0] (identityKey). Mirrors kvControllerWallet in
// kvstore_test.go.
func uhrpIdentityWallet(t *testing.T) (wallet.Interface, []byte) {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	return w, priv.PubKey().Compressed()
}

// buildUHRPBRC26Script signs and locks a canonical 5-content-field BRC-26
// UHRP advertisement via the real pushdrop.Lock path. The signer wallet w
// signs with counterparty=anyone — the symmetric partner of
// verifyBRC26Linkage's counterparty=identityKey check, exactly as a real
// advertiser's wallet would.
//
// Fix pass (cold review RISKS / spec item 6): forSelf is true, matching
// canonical producers (overlays/uhrp-server-basic
// createUHRPAdvertisement.ts calls `pushdrop.lock(fields, protocol, '1',
// 'anyone', true)`). This is load-bearing, not cosmetic: go-sdk's
// KeyDeriver.DerivePublicKey computes two different points depending on
// forSelf (wallet/key_deriver.go) — forSelf=true derives
// rootKey.DeriveChild(counterpartyKey, invoice) (the signer's OWN key,
// privately derivable by the signer); forSelf=false derives
// counterpartyKey.DeriveChild(rootKey, invoice) (the COUNTERPARTY's key,
// from the signer's point of view). verifyBRC26Linkage's own
// GetPublicKey call (uhrp_brc26.go) omits ForSelf entirely — defaulting
// false — which is the correct mirror image of a forSelf=true producer
// (BRC-42's symmetric/ECDH-style derivation makes
// signerPriv.DeriveChild(anyonePub) equal anyonePub's-counterpart
// verifierPriv.DeriveChild(signerPub), not signerPriv.DeriveChild(anyonePub)
// equal anyonePub.DeriveChild(signerPriv), which is what the old
// forSelf=false here produced). With the old forSelf=false, every
// locking key this helper built was the WRONG point: it would never
// equal what verifyBRC26Linkage's forSelf=false(default) derivation
// computes — this helper was silently building adverts that cannot be
// genuinely admitted. No test before this fix pass called this helper
// and then asserted a successful admit, so the mismatch went unnoticed.
func buildUHRPBRC26Script(t *testing.T, w wallet.Interface, identityPub, hash []byte, url string, expiry, size uint64) []byte {
	t.Helper()
	fields := [][]byte{
		identityPub,
		hash,
		[]byte(url),
		util.VarInt(expiry).Bytes(),
		util.VarInt(size).Bytes(),
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		fields,
		uhrpBRC26Protocol,
		uhrpBRC26KeyID,
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		true, // forSelf — see the fix-pass comment above
		true, // includeSignature: a BRC-26 advert carries an appended signature
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return s.Bytes()
}

// uhrpFreshHash returns a 32-byte content hash distinct per call (so tests
// built from fresh scripts never collide with each other or the golden
// vector by accident).
func uhrpFreshHash(t *testing.T, seed byte) []byte {
	t.Helper()
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed
	}
	return h
}

// --- tests: golden vector -------------------------------------------------

// TestUHRPBRC26_GoldenVectorAdmitted pins the canonical happy path against
// the shared cross-team parity vector: a correctly-signed BRC-26
// advertisement is admitted, and the stored metadata matches every field
// of the vector exactly. This is the one test in this file that proves
// real interop — the signature was produced by a different implementation
// than the one verifying it here.
func TestUHRPBRC26_GoldenVectorAdmitted(t *testing.T) {
	scriptBytes := uhrpGoldenScriptBytes(t)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected output 0 admitted, got %+v", inst)
	}
	raw, ok := inst.OutputMetadata[0]
	if !ok {
		t.Fatalf("expected metadata for output 0")
	}
	var entry UHRPEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if !entry.BRC26 {
		t.Fatalf("expected BRC26=true, got %+v", entry)
	}
	if entry.ContentHash != uhrpGoldenContentHash {
		t.Fatalf("ContentHash = %q, want %q", entry.ContentHash, uhrpGoldenContentHash)
	}
	if entry.URL != uhrpGoldenURL {
		t.Fatalf("URL = %q, want %q", entry.URL, uhrpGoldenURL)
	}
	if entry.IdentityKey != uhrpGoldenIdentityPub {
		t.Fatalf("IdentityKey = %q, want %q", entry.IdentityKey, uhrpGoldenIdentityPub)
	}
	if entry.Expiry != uhrpGoldenExpiry {
		t.Fatalf("Expiry = %d, want %d", entry.Expiry, uhrpGoldenExpiry)
	}
}

// TestUHRPBRC26_GoldenVectorTamperedHashRejected mutates one byte inside
// the golden vector's content-hash field (located dynamically via
// bytes.Index on the known hash bytes, not a hardcoded offset, so the test
// stays correct if the vector is ever replaced) and confirms the altered
// output is rejected: the appended signature was computed over the
// original field bytes, so changing any signed field breaks
// verifyBRC26Linkage's VerifySignature check.
func TestUHRPBRC26_GoldenVectorTamperedHashRejected(t *testing.T) {
	scriptBytes := uhrpGoldenScriptBytes(t)
	hashBytes, err := hex.DecodeString(uhrpGoldenContentHash)
	if err != nil {
		t.Fatalf("decode golden hash: %v", err)
	}
	idx := bytes.Index(scriptBytes, hashBytes)
	if idx < 0 {
		t.Fatalf("golden hash bytes not found in golden script — fixture changed?")
	}
	tampered := append([]byte{}, scriptBytes...)
	tampered[idx] ^= 0xff // flip one byte within the signed hash field

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, tampered), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected tampered advertisement rejected, got %+v", inst)
	}
}

// --- tests: fresh-constructed shape/signature rejects ---------------------

// TestUHRPBRC26_HTTPURLRejected confirms a properly-signed advertisement
// whose URL uses http:// (not https://) is rejected — canonical requires
// HTTPS (UHRPTopicManager.ts). The signature itself is fully valid; only
// the URL scheme is wrong, proving the HTTPS check is enforced
// independently of signature validity.
func TestUHRPBRC26_HTTPURLRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x01)
	scriptBytes := buildUHRPBRC26Script(t, w, idPub, hash, "http://example.com/insecure", 2000000000, 100)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected http:// advertisement rejected, got %+v", inst)
	}
}

// TestUHRPBRC26_WrongFieldCountRejected confirms a PushDrop output with
// fewer than the 6 required total fields (5 content + signature) is
// rejected rather than mistaken for a canonical BRC-26 advert.
func TestUHRPBRC26_WrongFieldCountRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x02)
	// Only 3 content fields (identityKey, hash, url) — missing expiry and
	// size — plus the appended signature makes 4 total, under the
	// required 6.
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		[][]byte{idPub, hash, []byte("https://example.com")},
		uhrpBRC26Protocol,
		uhrpBRC26KeyID,
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		false,
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
		t.Fatalf("expected wrong-field-count advertisement rejected, got %+v", inst)
	}
}

// TestUHRPBRC26_WrongSignerRejected tests the half of verifyBRC26Linkage
// that TestUHRPBRC26_GoldenVectorTamperedHashRejected does not reach: a
// properly-signed advertisement (the appended signature DOES verify under
// the claimed identityKey, over unmodified field data) whose embedded
// PushDrop locking key is then swapped to an unrelated key. The signature
// proves identityKey's holder signed this data; the locking-key swap
// proves the output itself is not actually locked to that same holder's
// BRC-42-derived key — a distinct attack from content tampering, and the
// second of verifyBRC26Linkage's two required checks.
func TestUHRPBRC26_WrongSignerRejected(t *testing.T) {
	w, idPub := uhrpIdentityWallet(t)
	hash := uhrpFreshHash(t, 0x03)
	scriptBytes := buildUHRPBRC26Script(t, w, idPub, hash, "https://example.com/ok", 2000000000, 100)

	// The PushDrop lock-before pattern always starts with a single direct
	// push of the compressed (33-byte) locking public key: opcode 0x21 at
	// offset 0, key bytes at [1:34]. Confirm that assumption before the
	// byte-surgery so a future encoding change fails loudly here instead
	// of silently corrupting an unrelated field.
	if len(scriptBytes) < 34 || scriptBytes[0] != 0x21 {
		t.Fatalf("locking script does not start with a 33-byte direct push as expected: %x", scriptBytes[:min(8, len(scriptBytes))])
	}
	unrelatedPriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new unrelated priv: %v", err)
	}
	unrelatedPub := unrelatedPriv.PubKey().Compressed()
	tampered := append([]byte{}, scriptBytes...)
	copy(tampered[1:34], unrelatedPub)

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, tampered), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst != nil && len(inst.OutputsToAdmit) != 0 {
		t.Fatalf("expected locking-key-swapped advertisement rejected, got %+v", inst)
	}
}

// --- tests: legacy coexistence + canonical coin semantics ------------------

// TestUHRPAdmit_LegacyStillAdmitted confirms Admit's legacy fallback path
// (classifyUHRPOutput) still admits a well-formed legacy
// OP_FALSE OP_RETURN "UHRP" advertisement end-to-end, now that BRC-26 is
// tried first — the two formats must coexist, not compete.
func TestUHRPAdmit_LegacyStillAdmitted(t *testing.T) {
	contentHash := HashContent([]byte("legacy coexistence"))
	scriptBytes, err := BuildUHRPScript(contentHash, "https://legacy.example.com/x", "text/plain")
	if err != nil {
		t.Fatalf("BuildUHRPScript: %v", err)
	}

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), nil)
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected legacy output 0 admitted, got %+v", inst)
	}
	var entry UHRPEntry
	if err := json.Unmarshal(inst.OutputMetadata[0], &entry); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if entry.BRC26 {
		t.Fatalf("expected BRC26=false for a legacy advertisement, got %+v", entry)
	}
	if entry.ContentHash != contentHash {
		t.Fatalf("ContentHash = %q, want %q", entry.ContentHash, contentHash)
	}
}

// TestUHRPAdmit_RetainsPreviousCoins pins the corrected canonical
// coinsToRetain divergence documented in Admit's comment: every previously
// admitted coin this tx spends is retained (not removed), matching
// UHRPTopicManager.ts's `coinsToRetain: previousCoins`.
func TestUHRPAdmit_RetainsPreviousCoins(t *testing.T) {
	contentHash := HashContent([]byte("retain test"))
	scriptBytes, err := BuildUHRPScript(contentHash, "https://example.com/retain", "")
	if err != nil {
		t.Fatalf("BuildUHRPScript: %v", err)
	}

	m := NewUHRPTopicManager()
	inst, err := m.Admit(txWith(t, scriptBytes), make([]anviloverlay.AdmittedOutput, 2))
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	if inst == nil {
		t.Fatal("expected non-nil instructions")
	}
	if len(inst.CoinsToRetain) != 2 {
		t.Fatalf("expected 2 retained coins, got %d (%+v)", len(inst.CoinsToRetain), inst.CoinsToRetain)
	}
	if len(inst.CoinsRemoved) != 0 {
		t.Fatalf("expected 0 removed coins, got %d", len(inst.CoinsRemoved))
	}
}
