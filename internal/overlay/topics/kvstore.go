package topics

// Canonical upstream primitive — KVStore (BRC-35 key-value tokens).
//
// **Hosted in Anvil today as a pragmatic transitional placement**; the
// long-term home is `bsv-blockchain/go-overlay-discovery-services` once
// that repo gains a topic-impl partition for non-SHIP/SLAP canonical
// primitives. To be PR'd upstream when that home exists; this file
// becomes a one-line re-export at that point. Same transitional story
// as ump.go / identity.go.
//
// Port source: `ts-stack`
// `packages/overlays/topics/src/kvstore/KVStoreTopicManager.ts` +
// `types.ts` (MCP-verified, head `29aff6e`, last commit 2026-05-11).
// Admission rules mirror the canonical TypeScript 1:1 modulo language
// idioms: PushDrop-decode → field-shape validation (legacy 5-field OR
// tagged 6-field, signature included in the count) → non-empty
// key+value → canonical ProtoWallet("anyone").verifySignature with the
// controller as counterparty. KVStore is the first Anvil topic that
// performs canonical signature verification at admission (UMP checks
// field shape only; Identity uses Certificate.Verify).
//
// SendBSV-Wallet consumes this topic to publish canonical BRC-35
// key-value records for cross-device wallet-settings sync (cold-storage
// address, fiat-currency preference, display toggles, tip-jar config,
// payment templates). Private values are BRC-2 self-encrypted client
// side (`sendbsv-enc:v1:<base64>`); Anvil sees only opaque value bytes
// plus the lookup keys (key, protocolID, controller, tags) it indexes.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// KVStoreTopicName is the BRC-87 canonical name for the BRC-35 key-value
// store publication topic.
const KVStoreTopicName = "tm_kvstore"

// kvProtocol field indices. Mirrors the canonical `kvProtocol` map in
// ts-stack kvstore/types.ts. The PushDrop wire layout is
// [protocolID, key, value, controller, tags, signature] for the tagged
// (6-field) format; the legacy format omits the tags field, leaving the
// signature at index 4.
const (
	kvFieldProtocolID = 0
	kvFieldKey        = 1
	kvFieldValue      = 2
	kvFieldController = 3
	kvFieldTags       = 4
	// kvExpectedFieldCount is len(kvProtocol) in the canonical types.ts
	// (protocolID, key, value, controller, tags, signature = 6). A tagged
	// token decodes to exactly this many fields; a legacy token to one
	// fewer (no tags field).
	kvExpectedFieldCount = 6
)

// KVStoreEntry is the metadata Anvil stores per admitted KVStore output.
// All fields are lookup keys the ls_kvstore service indexes; the
// encrypted/plaintext value itself is intentionally NOT retained (Anvil
// answers with output references, not values — the wallet fetches +
// decrypts the value client-side).
type KVStoreEntry struct {
	// Key is the UTF-8 KVStore key (canonical field[1]). Primary lookup
	// selector.
	Key string `json:"key"`
	// ProtocolID is the raw UTF-8 protocolID field (canonical field[0]),
	// e.g. `[1,"sendbsv settings"]`. Stored verbatim so the lookup can
	// match the canonical JSON-stringify comparison.
	ProtocolID string `json:"protocol_id"`
	// Controller is the hex-encoded controller identity pubkey
	// (canonical field[3]). The counterparty the admission signature is
	// verified against.
	Controller string `json:"controller"`
	// Tags are the optional UTF-8 tags (canonical field[4], tagged
	// format only). Absent/invalid-JSON tags decode to nil.
	Tags []string `json:"tags,omitempty"`
}

// kvDecoded holds the decoded-but-unverified KVStore output: the entry
// metadata plus the raw material the signature check needs.
type kvDecoded struct {
	entry      *KVStoreEntry
	dataFields [][]byte // fields with the trailing signature removed (the signed preimage)
	signature  []byte   // DER-encoded appended signature (canonical field[last])
	protocolID string   // raw UTF-8 protocolID field (== entry.ProtocolID)
	keyID      string   // UTF-8 key field used as the signature keyID
	controller []byte   // raw controller pubkey bytes (counterparty)
}

// KVStoreTopicManager admits BRC-35 KVStore tokens into tm_kvstore.
// Implements the canonical KVStoreTopicManager.ts logic using go-sdk's
// canonical ProtoWallet signature verification.
//
// Admission contract (matches KVStoreTopicManager.ts):
//
//  1. PushDrop-decode each output.
//  2. Require a legacy (5-field) OR tagged (6-field) shape — counts
//     include the appended signature.
//  3. Require non-empty key (field[1]) and value (field[2]).
//  4. Pop the trailing signature, verify it via
//     ProtoWallet("anyone").VerifySignature over the remaining fields'
//     concatenation, with the controller (field[3]) as counterparty,
//     protocolID parsed from field[0], and keyID = UTF-8(field[1]).
//  5. Admit the output. Per-output errors are silently skipped (matches
//     the TS console.debug skip).
//
// Unlike UMP/Identity (spent-by-overwrite → CoinsRemoved), KVStore
// retains previous coins: each key is its own token and updates spend
// the prior token through the normal UTXO path, so the topic manager
// returns coinsToRetain = previousCoins and removes nothing. This
// mirrors KVStoreTopicManager.ts's `coinsToRetain: previousCoins`.
type KVStoreTopicManager struct {
	anyoneWallet *wallet.ProtoWallet
}

// NewKVStoreTopicManager constructs a KVStore topic manager. It holds a
// single canonical "anyone" ProtoWallet for signature verification;
// construction of the anyone wallet is deterministic and never fails in
// practice, but a nil wallet is guarded at verify time.
func NewKVStoreTopicManager() *KVStoreTopicManager {
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypeAnyone})
	if err != nil {
		// The anyone constructor only builds a key deriver from a nil
		// root key; it cannot error. Guard defensively anyway so a
		// future SDK change surfaces as a clean admission-skip rather
		// than a panic.
		return &KVStoreTopicManager{anyoneWallet: nil}
	}
	return &KVStoreTopicManager{anyoneWallet: w}
}

// Admit evaluates a transaction for KVStore token outputs.
func (m *KVStoreTopicManager) Admit(txData []byte, previousUTXOs []anviloverlay.AdmittedOutput) (*anviloverlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("kvstore: invalid transaction: %w", err)
	}
	ctx := context.Background()

	var outputsToAdmit []int
	outputMetadata := make(map[int]json.RawMessage)

	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		d, err := decodeKVStore(out.LockingScript.Bytes())
		if err != nil || d == nil {
			continue
		}
		valid, err := m.verifySignature(ctx, d)
		if err != nil || !valid {
			// Signature failure or malformed crypto material — skip per
			// the canonical TS catch-and-continue.
			continue
		}
		outputsToAdmit = append(outputsToAdmit, i)
		if meta, err := json.Marshal(d.entry); err == nil {
			outputMetadata[i] = meta
		}
	}

	// KVStore retains previous coins (canonical coinsToRetain:
	// previousCoins). Each KVStore key is an independent token; updates
	// spend the prior token via the normal UTXO path, so nothing is
	// force-removed here.
	var coinsToRetain []int
	for i := range previousUTXOs {
		coinsToRetain = append(coinsToRetain, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsToRetain) == 0 {
		return nil, nil
	}

	return &anviloverlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  coinsToRetain,
		CoinsRemoved:   nil,
		OutputMetadata: outputMetadata,
	}, nil
}

// GetDocumentation returns the human-readable purpose of the topic.
func (m *KVStoreTopicManager) GetDocumentation() string {
	return "KVStore (BRC-35) Topic Manager: admits PushDrop tokens representing canonical key-value " +
		"records into an overlay. Wallets (SendBSV-Wallet) publish encrypted settings (cold-storage " +
		"address, fiat-currency preference, display toggles, tip-jar config, payment templates) as " +
		"BRC-35 KVStore tokens for cross-device sync. Anvil verifies each token's appended signature " +
		"against the controller's identity key using the canonical anyone-wallet scheme and admits if " +
		"valid; values stay opaque (client-side BRC-2 encrypted) and Anvil indexes only the lookup keys."
}

// GetMetadata returns machine-readable metadata.
func (m *KVStoreTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"brc":      35,
		"protocol": "kvstore",
		"purpose":  "canonical-key-value-record-publication",
	}
}

// verifySignature performs the canonical anyone-wallet signature check
// over a decoded KVStore output. Returns (false, nil) for any malformed
// crypto material so admission cleanly skips the output (matching the TS
// catch-and-continue); a non-nil error is reserved for unexpected wallet
// faults the caller may want to surface.
func (m *KVStoreTopicManager) verifySignature(ctx context.Context, d *kvDecoded) (bool, error) {
	if m.anyoneWallet == nil {
		return false, errors.New("kvstore: anyone wallet unavailable")
	}
	var protocol wallet.Protocol
	if err := json.Unmarshal([]byte(d.protocolID), &protocol); err != nil {
		return false, nil // protocolID field is not a valid [level, name] array
	}
	controllerPub, err := ec.PublicKeyFromBytes(d.controller)
	if err != nil {
		return false, nil // controller field is not a valid pubkey
	}
	sig, err := ec.FromDER(d.signature)
	if err != nil {
		return false, nil // signature field is not valid DER
	}
	data := make([]byte, 0)
	for _, f := range d.dataFields {
		data = append(data, f...)
	}
	res, err := m.anyoneWallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   protocol,
			KeyID:        d.keyID,
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: controllerPub},
		},
		Data:      data,
		Signature: sig,
	}, "")
	if err != nil {
		return false, nil
	}
	return res.Valid, nil
}

// ParseKVStoreOutput PushDrop-decodes a locking script and validates its
// KVStore field shape, returning the indexable entry. It does NOT verify
// the appended signature — admission (KVStoreTopicManager.Admit) does
// that; the lookup service uses this to re-derive the entry from an
// already-admitted output. Returns (entry, nil) for a KVStore-shaped
// output, (nil, nil) for a non-KVStore script.
//
// Exported so lookups/kvstore.go can re-derive KVStoreEntry without
// rebuilding the decode path.
func ParseKVStoreOutput(scriptBytes []byte) (*KVStoreEntry, error) {
	d, err := decodeKVStore(scriptBytes)
	if err != nil || d == nil {
		return nil, err
	}
	return d.entry, nil
}

// decodeKVStore decodes + shape-validates a KVStore locking script.
// Returns (nil, nil) for any non-KVStore-shaped script (so callers
// skip), and a populated *kvDecoded otherwise. Signature verification is
// the caller's responsibility.
func decodeKVStore(scriptBytes []byte) (*kvDecoded, error) {
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
	n := len(fields)

	// Field counts include the trailing signature. Tagged = 6, legacy = 5.
	hasTags := n == kvExpectedFieldCount
	isOldFormat := n == kvExpectedFieldCount-1
	if !hasTags && !isOldFormat {
		return nil, nil
	}

	keyBuf := fields[kvFieldKey]
	valBuf := fields[kvFieldValue]
	if len(keyBuf) == 0 || len(valBuf) == 0 {
		return nil, nil
	}

	// Pop the trailing signature; the remaining fields are the signed
	// preimage. controller (3) and protocolID (0) indices are unaffected
	// by the pop in both formats.
	signature := fields[n-1]
	dataFields := fields[:n-1]

	controller := fields[kvFieldController]
	protocolID := string(fields[kvFieldProtocolID])

	var tags []string
	if hasTags && len(fields[kvFieldTags]) > 0 {
		var t []string
		if err := json.Unmarshal(fields[kvFieldTags], &t); err == nil {
			// Invalid-JSON tags are treated as absent (matches the
			// canonical lookup's try/catch around the tags parse).
			tags = t
		}
	}

	entry := &KVStoreEntry{
		Key:        string(keyBuf),
		ProtocolID: protocolID,
		Controller: hex.EncodeToString(controller),
		Tags:       tags,
	}
	return &kvDecoded{
		entry:      entry,
		dataFields: dataFields,
		signature:  signature,
		protocolID: protocolID,
		keyID:      string(keyBuf),
		controller: controller,
	}, nil
}
