package topics

// Canonical upstream primitive — BRC-26 UHRP content-availability
// advertisements carried as PushDrop outputs, superseding the legacy
// OP_FALSE OP_RETURN "UHRP" advert that uhrp.go's classifyUHRPOutput still
// reads (read-only, for existing entries).
//
// Port sources:
//   - overlays/topics `uhrp/UHRPTopicManager.ts` (identifyAdmissibleOutputs):
//     field-count + hash-length + HTTPS + expiry/size validation.
//   - overlays/topics `uhrp/isTokenSignatureCorrectlyLinked.ts`: the
//     signature-linkage check this file ports as verifyBRC26Linkage.
//
// A canonical advert is a PushDrop output (go-sdk pushdrop.Decode) with
// fields [identityKey(33B), sha256(32B), https URL (UTF-8), varint
// expirySeconds, varint size] plus a trailing appended signature field (6
// pushed fields total). The signature is produced by the identityKey
// holder's own wallet with counterparty='anyone', protocol
// [2,'uhrp advertisement'], keyID '1' (see verifyBRC26Linkage) — the same
// BRC-42 "anyone can verify, only the identity key holder could have
// signed" pattern kvstore.go already uses for its controller signature.
//
// Divergence (documented, matches an existing Anvil pattern — see
// decodeKVStore / KVStoreTopicManager.verifySignature): canonical pops the
// signature field via a single mutating array and interleaves the
// signature-linkage check between the field-count check and the
// hash/URL/expiry checks. This port separates "shape" (decodeUHRPBRC26,
// used by both Admit and the lookup's read-only re-derivation) from
// "signature" (verifyBRC26Linkage, Admit-only — the lookup trusts that
// admission already verified it, exactly as KVStore's ParseKVStoreOutput
// does). The admit/reject verdict is identical either way; only which
// error fires first, for an input with more than one defect, can differ.
//
// Divergence: canonical's `result.fields.length < 5` check runs BEFORE the
// signature pop, so a 5-total-field output passes it but then indexes a
// now-4-element array at [4] (fileSize) — an out-of-bounds read that a JS
// Reader over `undefined` throws on, with the same practical effect as
// rejecting outright. This port requires >= 6 total fields (5 content +
// the trailing signature) up front, which is the same requirement by
// construction, not by relying on that an out-of-bounds access happens to
// throw.
//
// Fix pass (cold review): decodeUHRPBRC26 now also rejects a URL over 4096
// bytes, an expiry/size at or above 2^53 (canonical's readVarIntNum throws
// there — see uhrpBRC26MaxSafeVarInt), an identityKey that isn't exactly
// 33 bytes, an https URL with an empty host or an out-of-range port; and
// verifyBRC26Linkage now rejects a DER signature with trailing bytes. Each
// check's own comment explains the specific canonical behaviour it
// matches and cites what remains a known, narrower divergence.

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	neturl "net/url"
	"strconv"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// uhrpBRC26ProtocolName and uhrpBRC26KeyID are the canonical BRC-42
// protocol/keyID the signature and locking key are derived under —
// `[2, 'uhrp advertisement']` / `'1'` per isTokenSignatureCorrectlyLinked.ts.
const (
	uhrpBRC26ProtocolName = "uhrp advertisement"
	uhrpBRC26KeyID        = "1"
	// uhrpBRC26MinFields is 5 content fields + 1 trailing signature field.
	// See the package divergence note above.
	uhrpBRC26MinFields = 6
	// uhrpBRC26IdentityKeyLen and uhrpBRC26HashLen are the field lengths
	// spec item 1 names (33-byte compressed pubkey, 32-byte SHA-256).
	// Fix pass: canonical TS 4.1.1 rejects a 65-byte uncompressed
	// identityKey ("Signature is not properly linked" — @bsv/sdk's
	// ProtoWallet.getPublicKey only ever returns a compressed point, so an
	// uncompressed counterparty key never derives a matching one).
	// ec.PublicKeyFromBytes alone does not reject it (it accepts both
	// compressed and uncompressed points), so the length is now checked
	// explicitly in decodeUHRPBRC26, not just implied by key parsing.
	uhrpBRC26IdentityKeyLen = 33
	uhrpBRC26HashLen        = 32
	// uhrpBRC26MaxURLLen bounds the advertisement URL at admission.
	// Without it, go-sdk's PushDrop decoding (PUSHDATA4) allows a URL up to
	// ~16 MiB, and every by-hash / list lookup query decodes every
	// candidate record's URL — an unbounded URL is a heap blow-up on a
	// no-login route. decodeUHRPBRC26 is also the lookup's read-side
	// re-derivation (ParseUHRPOutput), so this one cap protects both
	// admission and lookup decoding.
	uhrpBRC26MaxURLLen = 4096
	// uhrpBRC26MaxSafeVarInt is 2^53, the JS Number.isSafeInteger boundary.
	// Canonical's readVarIntNum (ts-sdk primitives/utils.ts) throws "Number
	// can only safely store up to 53 bits" for any value at or above this —
	// not a theoretical nicety: JS numbers silently lose precision past
	// 2^53 instead of erroring on their own, so admitting an expiry/size at
	// or above it would let a throwaway key mint an advertisement that is
	// never treated as locally expired yet throws in every canonical
	// resolve() of its hash.
	uhrpBRC26MaxSafeVarInt = 1 << 53
)

// uhrpBRC26Protocol is the wallet.Protocol for signature + key derivation.
// SecurityLevel 2 is `wallet.SecurityLevelEveryAppAndCounterparty`, matching
// the canonical `[2, 'uhrp advertisement']` tuple.
var uhrpBRC26Protocol = wallet.Protocol{
	SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
	Protocol:      uhrpBRC26ProtocolName,
}

// uhrpBRC26Decoded holds a shape-validated (not yet signature-verified)
// canonical UHRP advert, plus everything verifyBRC26Linkage needs.
type uhrpBRC26Decoded struct {
	lockingPublicKey *ec.PublicKey
	identityKeyBytes []byte // raw field[0], 33 bytes
	identityKey      *ec.PublicKey
	contentHash      []byte // raw field[1], 32 bytes
	url              string
	expiry           uint64
	size             uint64
	signedFields     [][]byte // the 5 content fields, signature already removed
	signature        []byte
}

// toEntry builds the shared UHRPEntry metadata for an admitted (or,
// lookup-side, already-admitted) BRC-26 output.
func (d *uhrpBRC26Decoded) toEntry() *UHRPEntry {
	return &UHRPEntry{
		ContentHash: hex.EncodeToString(d.contentHash),
		URL:         d.url,
		BRC26:       true,
		IdentityKey: hex.EncodeToString(d.identityKeyBytes),
		Expiry:      int64(d.expiry), // #nosec G115 -- bounded < math.MaxInt64 by decodeUHRPBRC26
	}
}

// decodeUHRPBRC26 PushDrop-decodes a locking script and validates it as a
// canonical BRC-26 UHRP advertisement's SHAPE: field count, hash length,
// HTTPS URL, and expiry/size range. It does NOT verify the appended
// signature — Admit calls verifyBRC26Linkage separately for that; the
// lookup service's read-only re-derivation (an already-admitted output)
// skips it, mirroring ParseKVStoreOutput / decodeKVStore.
//
// Returns (nil, nil) only when the script does not PushDrop-decode at all
// (so the caller falls back to the legacy OP_RETURN classifier). Any
// PushDrop-shaped output that fails a BRC-26 shape check returns (nil,
// err) so Admit can log why — mirroring the canonical try/catch, which
// logs every one of these cases uniformly.
func decodeUHRPBRC26(scriptBytes []byte) (*uhrpBRC26Decoded, error) {
	if len(scriptBytes) == 0 {
		return nil, nil
	}
	s := script.NewFromBytes(scriptBytes)
	if s == nil {
		return nil, nil
	}
	decoded := pushdrop.Decode(s)
	if decoded == nil {
		return nil, nil // not PushDrop-shaped — maybe legacy OP_RETURN
	}
	if decoded.LockingPublicKey == nil {
		return nil, errors.New("uhrp: pushdrop output has no locking public key")
	}
	fields := decoded.Fields
	if len(fields) < uhrpBRC26MinFields {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 token: want >= %d fields (5 + signature), got %d", uhrpBRC26MinFields, len(fields))
	}
	signature := fields[len(fields)-1]
	content := fields[:len(fields)-1]

	if len(content[1]) != uhrpBRC26HashLen {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 hash length %d, want %d", len(content[1]), uhrpBRC26HashLen)
	}
	if len(content[2]) > uhrpBRC26MaxURLLen {
		return nil, fmt.Errorf("uhrp: BRC-26 advertisement URL exceeds %d bytes", uhrpBRC26MaxURLLen)
	}
	rawURL := string(content[2])
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 advertisement URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("uhrp: BRC-26 advertisement must be on HTTPS")
	}
	// Fix pass: require a non-empty host. parsed.Opaque is non-empty only
	// for a scheme:opaque form with no "//" at all (e.g. "https:host"),
	// which canonical's `new URL(...)` also admits — Opaque!="" skips this
	// check so that form stays admitted, matching canonical. When "//" IS
	// present (Opaque==""), an empty host ("https://", "https:",
	// "https://user@:443/x") is what canonical's URL constructor rejects as
	// "Invalid URL"; Go's net/url does not error on it by itself, so it is
	// checked explicitly here.
	if parsed.Opaque == "" && parsed.Hostname() == "" {
		return nil, errors.New("uhrp: BRC-26 advertisement URL has no host")
	}
	// Fix pass: require a valid port. net/url.Parse accepts any all-digit
	// port string with no range check (Port() returns "99999" unchanged);
	// canonical's URL constructor rejects a port outside 0-65535. This
	// narrow check does not attempt to replicate the WHATWG URL spec's full
	// numeric-host validation (canonical also rejects "https://999.1.1.1/x"
	// and "https://1.2.3.4.5/x" as malformed IPv4-shaped hosts; Go's
	// net/url does not, and that gap is left open as a known, narrow
	// divergence — out of scope for this fix).
	if p := parsed.Port(); p != "" {
		if n, perr := strconv.Atoi(p); perr != nil || n < 0 || n > 65535 {
			return nil, errors.New("uhrp: BRC-26 advertisement URL has an invalid port")
		}
	}
	expiry, err := util.NewReader(content[3]).ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 expiry varint: %w", err)
	}
	size, err := util.NewReader(content[4]).ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 size varint: %w", err)
	}
	if expiry < 1 || size < 1 {
		return nil, errors.New("uhrp: invalid BRC-26 expiry time or file size")
	}
	// Fix pass: canonical's readVarIntNum throws for any value at or above
	// 2^53 (see uhrpBRC26MaxSafeVarInt's comment). This replaces the
	// previous math.MaxInt64 bound, which let an advertisement with e.g.
	// expiry exactly 2^53 or size 2^62 admit here while every canonical
	// resolve() of its hash throws — Go's int64 could still hold such a
	// value without overflow; the point of this check is matching
	// canonical's own tighter safe-integer ceiling, not avoiding a Go-side
	// overflow.
	if expiry >= uhrpBRC26MaxSafeVarInt || size >= uhrpBRC26MaxSafeVarInt {
		return nil, errors.New("uhrp: BRC-26 expiry or size exceeds the canonical safe-integer range (2^53)")
	}
	if len(content[0]) != uhrpBRC26IdentityKeyLen {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 identityKey length %d, want %d", len(content[0]), uhrpBRC26IdentityKeyLen)
	}
	identityPub, err := ec.PublicKeyFromBytes(content[0])
	if err != nil {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 identityKey: %w", err)
	}

	return &uhrpBRC26Decoded{
		lockingPublicKey: decoded.LockingPublicKey,
		identityKeyBytes: content[0],
		identityKey:      identityPub,
		contentHash:      content[1],
		url:              rawURL,
		expiry:           expiry,
		size:             size,
		signedFields:     content,
		signature:        signature,
	}, nil
}

// verifyBRC26Linkage ports isTokenSignatureCorrectlyLinked.ts: the
// signature must verify, under ProtoWallet('anyone'), protocol
// [2,'uhrp advertisement'], keyID '1', counterparty = the claimed
// identityKey, over the concatenation of the 5 content fields — AND the
// public key the same derivation yields must equal the PushDrop locking
// key. Both must hold for a properly-linked advertisement: the first
// proves identityKey's holder signed it; the second proves the output is
// actually locked to that same derivation (not to an unrelated key).
func (u *UHRPTopicManager) verifyBRC26Linkage(ctx context.Context, d *uhrpBRC26Decoded) (bool, error) {
	if u.anyoneWallet == nil {
		return false, errors.New("uhrp: anyone wallet unavailable")
	}
	// Fix pass: strict DER. go-sdk's ec.FromDER (encoding/asn1.Unmarshal
	// under the hood) silently accepts trailing bytes after the
	// signature's ASN.1 SEQUENCE and simply ignores them; canonical's DER
	// decoder does not. Parsed directly here (not via ec.FromDER) so the
	// leftover bytes asn1.Unmarshal reports can be checked — without this,
	// a byte-distinct "different" signature field (same leading SEQUENCE,
	// arbitrary trailing garbage) still verifies under the same key here,
	// while canonical would reject it outright.
	var sig ec.Signature
	rest, err := asn1.Unmarshal(d.signature, &sig)
	if err != nil {
		return false, fmt.Errorf("uhrp: signature is not valid DER: %w", err)
	}
	if len(rest) != 0 {
		return false, errors.New("uhrp: signature DER encoding has trailing bytes")
	}
	data := make([]byte, 0)
	for _, f := range d.signedFields {
		data = append(data, f...)
	}
	counterparty := wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: d.identityKey}
	verifyRes, err := u.anyoneWallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   uhrpBRC26Protocol,
			KeyID:        uhrpBRC26KeyID,
			Counterparty: counterparty,
		},
		Data:      data,
		Signature: &sig,
	}, "")
	if err != nil {
		return false, fmt.Errorf("uhrp: signature verification errored: %w", err)
	}
	if !verifyRes.Valid {
		return false, nil
	}

	pubRes, err := u.anyoneWallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   uhrpBRC26Protocol,
			KeyID:        uhrpBRC26KeyID,
			Counterparty: counterparty,
		},
	}, "")
	if err != nil {
		return false, fmt.Errorf("uhrp: derived public key errored: %w", err)
	}
	return pubRes.PublicKey.IsEqual(d.lockingPublicKey), nil
}
