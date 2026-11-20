package topics

// Canonical upstream primitive — MessageBox host advertisement
// (tm_messagebox).
//
// Port source: overlay-express-examples
// `src/services/message-box/MessageBoxTopicManager.ts`, pinned commit
// 481c42ed315279c17363e8b6d4c92401c8540fb7 (MCP-verified via brc100-mcp
// read_file, source_id "overlay-express-examples").
//
// Admission mirrors the canonical identifyAdmissibleOutputs
// (MessageBoxTopicManager.ts:35-104) 1:1 modulo language idioms:
// PushDrop-decode -> pop the trailing field as the signature
// (MessageBoxTopicManager.ts:60-61) -> field[0] = identity key, non-empty
// (:65-70) -> field[1] = host, non-empty + valid UTF-8 (:65-76) -> verify
// the signature with the canonical "anyone" ProtoWallet over the
// concatenation of the remaining fields (:79-80), counterparty =
// hex(field[0]) (:81, :87), protocolID = [1, "messagebox advertisement"]
// (:88), keyID = "1" (:89). Like canon, every previous coin is retained
// (coinsToRetain: previousCoins, MessageBoxTopicManager.ts:96-99) — an
// identity may hold more than one live advert at once, and a spend
// (ls_messagebox's OutputSpent) removes just that one.
//
// Divergences (interop-priority rule: executable interop with the
// canonical MessageBoxClient.ts wins):
//
//   - UTF-8 strictness. Canon's host decode (Utils.toUTF8,
//     MessageBoxTopicManager.ts:65-71) wraps a non-fatal TextDecoder,
//     which silently substitutes malformed byte sequences rather than
//     rejecting them; whether that ever actually throws in practice is
//     UNCERTAIN (the @bsv/sdk implementation was not independently
//     re-verified here). This port uses Go's utf8.Valid and refuses a
//     host field containing invalid UTF-8 outright, per the explicit
//     admission rule the spec states. Only adversarial/malformed byte
//     sequences diverge — a canonical client-built advert
//     (MessageBoxClient.ts:1296-1299 anointHost) always writes
//     well-formed UTF-8, so this is strictly more conservative than
//     canon, never less.
//   - Decode-failure narration. Canon's outer try/catch logs every skip
//     reason, including "not PushDrop at all"
//     (MessageBoxTopicManager.ts:92-93 console.warn). This port follows
//     Anvil's own established per-topic convention instead (kvstore.go,
//     ump.go): a non-PushDrop or wrong-shape output is skipped silently;
//     only a messagebox-shaped output that fails a specific check (empty
//     field, bad UTF-8, bad signature) is logged, via admitLogger.skip.
//     No admission outcome differs — this is a logging-verbosity
//     divergence only.
//   - OutputMetadata (the legacy v1/v2 per-output metadata map) is not
//     populated. The v3 Adapter (adapter.go) drops it unconditionally
//     ("OutputMetadata is intentionally dropped at the adapter
//     boundary") and tm_messagebox is registered only on the v3 path, so
//     the field would be dead weight; lookups/messagebox.go re-derives
//     everything it needs from the admitted output directly, exactly
//     like kvstore_lookup.go does for tm_kvstore.
//
// See messagebox_lookup.go and lookups/messagebox.go for the lookup-side
// divergences (tie-break order, host exact-match casing).

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// MessageBoxTopicName is the BRC-87 canonical name for the MessageBox
// host-advertisement publication topic.
const MessageBoxTopicName = "tm_messagebox"

// Canonical signature-check constants (MessageBoxTopicManager.ts:81-89
// and MessageBoxClient.ts:1303-1304). Unlike KVStore, neither the
// protocol name nor the keyID is an on-chain field here: both are fixed
// by the protocol itself, not chosen by the advertiser.
const (
	messageBoxProtocolName = "messagebox advertisement"
	messageBoxKeyID        = "1"
)

// messageBoxProtocol is the canonical protocolID [1, "messagebox
// advertisement"] used for the appended-signature check. Exported as a
// var (not const — wallet.Protocol is a struct) so tests can reuse it
// when building a canonical-shaped advert.
var messageBoxProtocol = wallet.Protocol{
	SecurityLevel: wallet.SecurityLevelEveryApp,
	Protocol:      messageBoxProtocolName,
}

// MessageBoxAdvertEntry is the metadata Anvil stores per admitted
// MessageBox advertisement output.
type MessageBoxAdvertEntry struct {
	// IdentityKey is the hex-encoded identity public key (field[0]) this
	// advert names — the recipient whose MessageBox the advert claims is
	// hosted at Host.
	IdentityKey string `json:"identityKey"`
	// Host is the raw UTF-8 host URL (field[1]), exactly as the
	// advertiser wrote it on-chain — not normalised. ls_messagebox's
	// optional host= query matches this raw value exactly, mirroring
	// canon's exact Mongo filter (MessageBoxStorage.ts:61-78);
	// messaging.HomeResolver does its own normalisation on top of the
	// unfiltered per-identityKey result (decision 2).
	Host string `json:"host"`
}

// mbDecoded holds a decoded-but-unverified MessageBox advert: the entry
// metadata plus the raw material the signature check needs.
type mbDecoded struct {
	entry          *MessageBoxAdvertEntry
	dataFields     [][]byte // fields with the trailing signature removed (the signed preimage)
	signature      []byte   // DER-encoded appended signature (canonical field[last])
	identityKeyRaw []byte   // raw identity-key bytes (field[0]) — the verify-time counterparty
}

// MessageBoxTopicManager admits BRC-33-style MessageBox host
// advertisements into tm_messagebox. Implements the canonical
// MessageBoxTopicManager.ts logic using go-sdk's canonical ProtoWallet
// signature verification.
type MessageBoxTopicManager struct {
	anyoneWallet *wallet.ProtoWallet
	log          admitLogger
}

// NewMessageBoxTopicManager constructs a MessageBox topic manager. It
// holds a single canonical "anyone" ProtoWallet for signature
// verification; construction of the anyone wallet is deterministic and
// never fails in practice, but a nil wallet is guarded at verify time.
//
// Pass WithLogger to surface per-output admission-skip reasons; with no
// options the manager stays silent, matching Anvil's other canonical
// ports.
func NewMessageBoxTopicManager(opts ...TopicOption) *MessageBoxTopicManager {
	log := newAdmitLogger(opts...)
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypeAnyone})
	if err != nil {
		// The anyone constructor only builds a key deriver from a nil
		// root key; it cannot error. Guard defensively anyway so a
		// future SDK change surfaces as a clean admission-skip rather
		// than a panic.
		return &MessageBoxTopicManager{anyoneWallet: nil, log: log}
	}
	return &MessageBoxTopicManager{anyoneWallet: w, log: log}
}

// Admit evaluates a transaction for MessageBox advertisement outputs.
func (m *MessageBoxTopicManager) Admit(txData []byte, previousUTXOs []anviloverlay.AdmittedOutput) (*anviloverlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("messagebox: invalid transaction: %w", err)
	}
	ctx := context.Background()

	var outputsToAdmit []int
	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		d, err := decodeMessageBoxAdvert(out.LockingScript.Bytes())
		if err != nil || d == nil {
			// Not a MessageBox-shaped output (non-PushDrop, or fewer
			// than 2 fields left after popping the signature) — skip
			// silently, matching Anvil's own shape-mismatch convention.
			continue
		}
		if valid, reason := m.verifySignature(ctx, d); !valid {
			// Decoded as a MessageBox advert but failed a specific
			// check (empty/invalid host, bad signature). Log the
			// reason; still just a skip, never a 4xx.
			m.log.skip(MessageBoxTopicName, i, reason)
			continue
		}
		outputsToAdmit = append(outputsToAdmit, i)
	}

	// MessageBox retains previous coins (canonical coinsToRetain:
	// previousCoins, MessageBoxTopicManager.ts:97-99). An identity can
	// hold more than one live advert; updates/revocations go through the
	// normal UTXO spend path, so nothing is force-removed here.
	var coinsToRetain []int
	for i := range previousUTXOs {
		coinsToRetain = append(coinsToRetain, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsToRetain) == 0 {
		m.log.nothingAdmitted(MessageBoxTopicName)
		return nil, nil
	}

	return &anviloverlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  coinsToRetain,
		CoinsRemoved:   nil,
	}, nil
}

// GetDocumentation returns the human-readable purpose of the topic.
func (m *MessageBoxTopicManager) GetDocumentation() string {
	return "MessageBox Topic Manager: admits PushDrop tokens advertising which host routes a " +
		"recipient identity's messages. A recipient (or its wallet, on its behalf) anoints a host " +
		"by signing [identityKey, host] with its own key; Anvil verifies that signature against the " +
		"canonical anyone-wallet scheme and admits if valid. ls_messagebox answers host lookups by " +
		"identity key for message routing (BRC-33)."
}

// GetMetadata returns machine-readable metadata.
func (m *MessageBoxTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"brc":      33,
		"protocol": "messagebox",
		"purpose":  "messagebox-host-advertisement",
	}
}

// verifySignature performs the canonical anyone-wallet signature check
// over a decoded MessageBox advert. Returns (false, reason) for any
// invalid or malformed crypto material so admission cleanly skips the
// output while giving the caller a human-readable reason to log. Returns
// (true, nil) only on a valid signature.
func (m *MessageBoxTopicManager) verifySignature(ctx context.Context, d *mbDecoded) (bool, error) {
	if m.anyoneWallet == nil {
		return false, errors.New("anyone wallet unavailable")
	}
	identityPub, err := ec.PublicKeyFromBytes(d.identityKeyRaw)
	if err != nil {
		return false, fmt.Errorf("identity key field is not a valid public key: %w", err)
	}
	sig, err := ec.FromDER(d.signature)
	if err != nil {
		return false, fmt.Errorf("signature field is not valid DER: %w", err)
	}
	data := make([]byte, 0)
	for _, f := range d.dataFields {
		data = append(data, f...)
	}
	res, err := m.anyoneWallet.VerifySignature(ctx, wallet.VerifySignatureArgs{
		EncryptionArgs: wallet.EncryptionArgs{
			ProtocolID:   messageBoxProtocol,
			KeyID:        messageBoxKeyID,
			Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: identityPub},
		},
		Data:      data,
		Signature: sig,
	}, "")
	if err != nil {
		return false, fmt.Errorf("signature verification errored: %w", err)
	}
	if !res.Valid {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

// ParseMessageBoxOutput PushDrop-decodes a locking script and validates
// its MessageBox field shape, returning the indexable entry. It does NOT
// verify the appended signature — admission (MessageBoxTopicManager.Admit)
// does that; the lookup service uses this to re-derive the entry from an
// already-admitted output. Returns (entry, nil) for a MessageBox-shaped
// output, (nil, nil) for a non-MessageBox script.
//
// Exported so lookups/messagebox.go can re-derive MessageBoxAdvertEntry
// without rebuilding the decode path.
func ParseMessageBoxOutput(scriptBytes []byte) (*MessageBoxAdvertEntry, error) {
	d, err := decodeMessageBoxAdvert(scriptBytes)
	if err != nil || d == nil {
		return nil, err
	}
	return d.entry, nil
}

// decodeMessageBoxAdvert decodes + shape-validates a MessageBox locking
// script. Returns (nil, nil) for any non-MessageBox-shaped script (so
// callers skip), and a populated *mbDecoded otherwise. Signature
// verification is the caller's responsibility.
func decodeMessageBoxAdvert(scriptBytes []byte) (*mbDecoded, error) {
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
	if len(fields) == 0 {
		// Nothing to pop as a signature, let alone an identity key or
		// host. Mirrors canon's destructuring-of-empty-array outcome
		// (both identityKeyBuf and hostBuf come back empty/undefined).
		return nil, nil
	}

	// Pop the trailing signature; whatever remains is the signed
	// preimage (MessageBoxTopicManager.ts:58-61). Canon does not assert
	// an exact field count beyond this — it destructures the first two
	// of whatever is left and treats a missing one as empty.
	signature := fields[len(fields)-1]
	dataFields := fields[:len(fields)-1]

	var identityKeyBuf, hostBuf []byte
	if len(dataFields) > 0 {
		identityKeyBuf = dataFields[0]
	}
	if len(dataFields) > 1 {
		hostBuf = dataFields[1]
	}
	if len(identityKeyBuf) == 0 || len(hostBuf) == 0 {
		// Empty field(s) — matches the canonical
		// "[ADMISSIBILITY] Output skipped due to empty field(s)" skip.
		return nil, nil
	}
	if !utf8.Valid(hostBuf) {
		// Invalid UTF-8 host — matches the canonical
		// "[ADMISSIBILITY] Output skipped due to UTF-8 decoding
		// failure" skip. See the UTF-8-strictness divergence above.
		return nil, nil
	}

	entry := &MessageBoxAdvertEntry{
		IdentityKey: hex.EncodeToString(identityKeyBuf),
		Host:        string(hostBuf),
	}
	return &mbDecoded{
		entry:          entry,
		dataFields:     dataFields,
		signature:      signature,
		identityKeyRaw: identityKeyBuf,
	}, nil
}
