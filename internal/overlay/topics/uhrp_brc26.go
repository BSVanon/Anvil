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

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	neturl "net/url"

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
	// uhrpBRC26IdentityKeyLen, uhrpBRC26HashLen mirror the field lengths
	// spec item 1 names (33-byte compressed pubkey, 32-byte SHA-256).
	// Canonical only explicitly checks the hash length (fields[1]); the
	// identityKey length is enforced implicitly by ec.PublicKeyFromBytes
	// refusing anything that is not a valid compressed/uncompressed point,
	// matching how the TS side would fail inside PublicKey construction
	// for a bad-length field rather than via an explicit length check.
	uhrpBRC26HashLen = 32
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
	rawURL := string(content[2])
	parsed, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("uhrp: invalid BRC-26 advertisement URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, errors.New("uhrp: BRC-26 advertisement must be on HTTPS")
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
	// Go stores Expiry as int64; a VarInt can carry a uint64. Canonical has
	// no equivalent bound (JS numbers silently lose precision instead) — a
	// defensive, explicitly-flagged divergence rather than a silent
	// sign-flip on conversion.
	if expiry > math.MaxInt64 || size > math.MaxInt64 {
		return nil, errors.New("uhrp: BRC-26 expiry or size exceeds the supported range")
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
	sig, err := ec.FromDER(d.signature)
	if err != nil {
		return false, fmt.Errorf("uhrp: signature is not valid DER: %w", err)
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
		Signature: sig,
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
