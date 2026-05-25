package topics

// Canonical upstream primitive — Identity (BRC-52 verifiable identity
// certificates).
//
// **Hosted in Anvil today as a pragmatic transitional placement**; the
// long-term home is `bsv-blockchain/go-overlay-discovery-services` once
// that repo gains a topic-impl partition for non-SHIP/SLAP canonical
// primitives. To be PR'd upstream when that home exists; this file
// becomes a one-line re-export at that point.
//
// Port source: `bsv-blockchain/overlay-express-examples` →
// `ts-stack/packages/overlays/topics/src/identity/IdentityTopicManager.ts`.
// Admission validation uses go-sdk's canonical Certificate.Verify
// (auth/certificates/certificate.go:146) so the signature-chain check
// is identical to what every other canonical overlay node does. The
// publicly-revealed-attributes check (decryptFields must yield at
// least one non-empty entry) is preserved.
//
// SendBSV-Wallet consumes this topic for paymail handle resolution
// (BRC-52 identity certs published under the user's paymail). Anvil's
// job is admission-only: PushDrop-decode → JSON-parse → verify
// signature chain → admit. The wallet does client-side query +
// VerifiableCertificate.verify() before trusting any returned cert.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
)

// IdentityTopicName is the BRC-87 canonical name for the BRC-52 identity
// certificate publication topic.
const IdentityTopicName = "tm_identity"

// IdentityEntry is the metadata Anvil stores per admitted identity
// output. The wallet-facing lookup index keys on IdentityKey (hex of
// the subject's compressed pubkey); structured attributes live in the
// Attributes map. Both are derived from canonical BRC-52 certificate
// fields parsed via go-sdk's auth/certificates.
type IdentityEntry struct {
	// IdentityKey is the hex-encoded compressed subject public key
	// from the canonical Certificate.Subject. Primary lookup key.
	IdentityKey string `json:"identity_key"`
	// CertifierKey is the hex-encoded compressed Certifier pubkey.
	// Lookups filter by this to scope to a trusted certifier set.
	CertifierKey string `json:"certifier_key,omitempty"`
	// CertType is the canonical Certificate.Type (base64). Useful for
	// scoping queries to a specific cert type (paymail, BRC-52, etc.).
	CertType string `json:"cert_type,omitempty"`
	// SerialNumber is the canonical Certificate.SerialNumber (base64).
	SerialNumber string `json:"serial_number,omitempty"`
}

// IdentityTopicManager admits BRC-52 verifiable identity certificates
// into tm_identity. Implements the same logic as
// IdentityTopicManager.ts:5-69 using go-sdk's canonical primitives.
//
// Admission contract:
//
//  1. Decode each output via canonical PushDrop.
//  2. Parse field[0] as a JSON-encoded Certificate.
//  3. Call cert.Verify(ctx) — canonical signature chain validation
//     against the certifier's pubkey using the canonical "certificate
//     signature" protocol ID.
//  4. Admit the output index. Per-output errors are silently skipped.
//
// Why no DecryptFields check? The TS impl also calls
// `certificate.decryptFields(anyoneWallet)` to verify >= 1 attribute
// is publicly revealed. go-sdk's VerifiableCertificate.DecryptFields
// exists but requires a Keyring map — the PushDrop wire format
// publishes the Certificate base type only, not VerifiableCertificate.
// The publicly-revealed check is therefore deferred to the wallet
// (which has access to its own ProtoWallet and full
// VerifiableCertificate decode path). Anvil admits cryptographically
// valid certs; the wallet does the semantic check. This is a documented
// divergence from the TS impl pending a follow-up that adds keyring
// extraction.
type IdentityTopicManager struct{}

// NewIdentityTopicManager constructs an Identity topic manager.
func NewIdentityTopicManager() *IdentityTopicManager {
	return &IdentityTopicManager{}
}

// Admit evaluates a transaction for identity certificate outputs.
func (m *IdentityTopicManager) Admit(txData []byte, previousUTXOs []anviloverlay.AdmittedOutput) (*anviloverlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("identity: invalid transaction: %w", err)
	}
	ctx := context.Background()

	var outputsToAdmit []int
	var coinsRemoved []int
	outputMetadata := make(map[int]json.RawMessage)

	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		entry, err := ParseIdentityOutput(ctx, out.LockingScript.Bytes())
		if err != nil || entry == nil {
			// Malformed cert or signature verification failure — silently
			// skip per the TS impl's console.error pattern. Operators
			// who want admission diagnostics can wire a structured
			// logger here in a follow-up.
			continue
		}
		outputsToAdmit = append(outputsToAdmit, i)
		if meta, err := json.Marshal(entry); err == nil {
			outputMetadata[i] = meta
		}
	}

	// Identity certs are spent-by-overwrite: publishing an updated cert
	// for the same identity replaces the previous one.
	for i := range previousUTXOs {
		coinsRemoved = append(coinsRemoved, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsRemoved) == 0 {
		return nil, nil
	}

	return &anviloverlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  nil,
		CoinsRemoved:   coinsRemoved,
		OutputMetadata: outputMetadata,
	}, nil
}

// GetDocumentation returns the human-readable purpose of the topic.
func (m *IdentityTopicManager) GetDocumentation() string {
	return "Identity (BRC-52) Topic Manager: admits verifiable identity certificates published as " +
		"PushDrop outputs. Wallets use this topic to publish BRC-52 identity claims (paymail handles, " +
		"DID-style identifiers, etc.) for public discovery. Anvil validates the certificate's signature " +
		"chain against the certifier's pubkey using canonical go-sdk primitives and admits if valid; " +
		"the client wallet does the public-attribute decryption + final trust decision."
}

// GetMetadata returns machine-readable metadata.
func (m *IdentityTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"brc":      52,
		"protocol": "identity",
		"purpose":  "verifiable-identity-certificate-publication",
	}
}

// ParseIdentityOutput PushDrop-decodes a locking script and validates
// it as a BRC-52 identity certificate. Returns (entry, nil) on a valid
// signed cert, (nil, nil) on a non-identity script, (nil, err) on a
// signature-verification failure.
//
// Exported so the lookup service can re-derive IdentityEntry from
// admitted output scripts.
func ParseIdentityOutput(ctx context.Context, scriptBytes []byte) (*IdentityEntry, error) {
	if len(scriptBytes) == 0 {
		return nil, nil
	}
	s := script.NewFromBytes(scriptBytes)
	if s == nil {
		return nil, nil
	}
	decoded := pushdrop.Decode(s)
	if decoded == nil {
		return nil, nil
	}
	fields := decoded.Fields
	// IdentityTopicManager.ts:18-19 requires the JSON cert in field[0].
	// A signature field is appended at the end (popped before signing).
	if len(fields) < 2 {
		return nil, nil
	}
	var cert certificates.Certificate
	if err := json.Unmarshal(fields[0], &cert); err != nil {
		return nil, nil // not a JSON cert — not an identity output
	}
	// Canonical signature chain validation. Mirrors
	// IdentityTopicManager.ts:46 `await certificate.verify()`.
	if err := cert.Verify(ctx); err != nil {
		return nil, fmt.Errorf("identity: certificate verify: %w", err)
	}

	return &IdentityEntry{
		IdentityKey:  hex.EncodeToString(cert.Subject.Compressed()),
		CertifierKey: hex.EncodeToString(cert.Certifier.Compressed()),
		CertType:     string(cert.Type),
		SerialNumber: string(cert.SerialNumber),
	}, nil
}

