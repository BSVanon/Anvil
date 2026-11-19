// Package topics contains overlay topic managers for the Anvil overlay engine.
//
// Each topic manager implements overlay.TopicManager and decides which
// transaction outputs are relevant to its topic.
package topics

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// UHRPTopicName is the BRC-87 standard name for the UHRP topic.
const UHRPTopicName = "tm_uhrp"

// UHRPProtocolID is the protocol identifier in BRC-48 push-drop scripts.
const UHRPProtocolID = "UHRP"

// UHRPEntry is the metadata stored for each admitted UHRP output, legacy
// OP_RETURN or canonical BRC-26 PushDrop alike.
type UHRPEntry struct {
	// ContentHash is the SHA-256 hash of the hosted file.
	ContentHash string `json:"content_hash"`
	// URL is where the content can be fetched.
	URL string `json:"url,omitempty"`
	// ContentType is the MIME type of the hosted file. Legacy-only;
	// canonical BRC-26 adverts carry no content-type field.
	ContentType string `json:"content_type,omitempty"`
	// BRC26 marks this entry as a canonical BRC-26 PushDrop advertisement
	// rather than a legacy OP_FALSE OP_RETURN advertisement. The zero
	// value (false) is correct for every legacy entry, including ones
	// stored before this field existed.
	BRC26 bool `json:"brc26,omitempty"`
	// IdentityKey is the hex-encoded 33-byte compressed host public key
	// (BRC-26 field[0]). Empty for legacy entries.
	IdentityKey string `json:"identity_key,omitempty"`
	// Expiry is the BRC-26 advertisement's expiry as an absolute
	// Unix-seconds timestamp (field[3]). Confirmed against the canonical
	// resolver, which skips an advert once `expiryTime < currentTime`
	// (ts-sdk storage/StorageDownloader.ts) — not a relative duration.
	// Zero for legacy entries, which have no expiry concept.
	Expiry int64 `json:"expiry,omitempty"`
}

// UHRPTopicManager implements overlay.TopicManager for BRC-26 UHRP.
//
// It admits two shapes of output:
//
//   - Canonical BRC-26: a PushDrop output carrying [identityKey(33B),
//     sha256(32B), https URL, varint expirySeconds, varint size] plus a
//     trailing signature, validated by decodeUHRPBRC26 + verifyBRC26Linkage
//     (uhrp_brc26.go — ported from UHRPTopicManager.ts +
//     isTokenSignatureCorrectlyLinked.ts). Being a real PushDrop output,
//     this format is spendable: revoking an advertisement is an ordinary
//     spend of its UTXO.
//   - Legacy: OP_FALSE OP_RETURN "UHRP" <sha256_hash_hex> [<url>]
//     [<content_type>], read-only. OP_RETURN outputs are unspendable, so
//     a legacy advertisement can never be revoked — admitted as-is so
//     existing entries keep resolving.
//
// When an admitted output (of either shape) is later spent, the lookup
// service's own index drops it unconditionally: the engine notifies every
// registered lookup via OutputSpent regardless of what Admit returns here
// (go-overlay-services@v1.3.1 engine.go's markSpentAndNotify /
// notifySpentOutputs). What Admit's CoinsToRetain/CoinsRemoved actually
// governs is the OVERLAY ENGINE'S OWN storage row for that spent coin
// (used for GASP provenance, independent of the lookup index above):
// commitTopicOutputs (engine.go:594-623) calls separateRetainedCoins
// (engine.go:628-653) to split a tx's spent coins into "retained" (every
// index named in CoinsToRetain — kept, marked consumed-by the new tx) and
// everything else, which is deleted outright. Canonical UHRPTopicManager.ts
// mirrors this exactly: coinsToRetain is the full previousCoins list when
// at least one output is admitted, and an empty list when none is (its
// outer catch's `{coinsToRetain: [], outputsToAdmit: []}`) — see Admit's
// comment below for the ported rule and its one flagged divergence.
type UHRPTopicManager struct {
	log          admitLogger
	anyoneWallet *wallet.ProtoWallet
}

// NewUHRPTopicManager creates a UHRP topic manager. It holds a single
// canonical "anyone" ProtoWallet for BRC-26 signature-linkage verification
// (see verifyBRC26Linkage); construction of the anyone wallet is
// deterministic and never fails in practice, but a nil wallet is guarded
// at verify time. Pass WithLogger to surface per-output admission-skip
// reasons; with no options the manager stays silent.
func NewUHRPTopicManager(opts ...TopicOption) *UHRPTopicManager {
	log := newAdmitLogger(opts...)
	w, err := wallet.NewProtoWallet(wallet.ProtoWalletArgs{Type: wallet.ProtoWalletArgsTypeAnyone})
	if err != nil {
		// The anyone constructor only builds a key deriver from a nil
		// root key; it cannot error. Guard defensively anyway so a
		// future SDK change surfaces as a clean admission-skip rather
		// than a panic (mirrors kvstore.go's identical guard).
		return &UHRPTopicManager{log: log, anyoneWallet: nil}
	}
	return &UHRPTopicManager{log: log, anyoneWallet: w}
}

// Admit evaluates a transaction for UHRP content advertisements, canonical
// BRC-26 PushDrop first, falling back to the legacy OP_RETURN format for
// any output that isn't PushDrop-shaped.
func (u *UHRPTopicManager) Admit(txData []byte, previousUTXOs []overlay.AdmittedOutput) (*overlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}
	ctx := context.Background()

	var outputsToAdmit []int
	outputMetadata := make(map[int]json.RawMessage)

	for i, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}
		scriptBytes := out.LockingScript.Bytes()

		brc26, decErr := decodeUHRPBRC26(scriptBytes)
		if decErr != nil {
			// PushDrop-shaped but fails a canonical BRC-26 shape check
			// (field count / hash length / HTTPS / expiry / size).
			u.log.skip(UHRPTopicName, i, decErr)
			continue
		}
		if brc26 != nil {
			ok, linkErr := u.verifyBRC26Linkage(ctx, brc26)
			if linkErr != nil {
				u.log.skip(UHRPTopicName, i, linkErr)
				continue
			}
			if !ok {
				u.log.skip(UHRPTopicName, i, "signature is not properly linked to identityKey")
				continue
			}
			outputsToAdmit = append(outputsToAdmit, i)
			if meta, merr := json.Marshal(brc26.toEntry()); merr == nil {
				outputMetadata[i] = meta
			}
			continue
		}

		// Not PushDrop-shaped at all — try the legacy format.
		entry, reason := classifyUHRPOutput(scriptBytes)
		if entry == nil {
			if reason != "" {
				// UHRP-tagged OP_RETURN whose hash field is malformed —
				// log the skip reason so a bad advertisement is
				// diagnosable. Non-UHRP outputs (reason == "") are silent.
				u.log.skip(UHRPTopicName, i, reason)
			}
			continue
		}
		outputsToAdmit = append(outputsToAdmit, i)
		if meta, merr := json.Marshal(entry); merr == nil {
			outputMetadata[i] = meta
		}
	}

	// Fix pass (cold review B2): canonical UHRPTopicManager.ts's
	// identifyAdmissibleOutputs wraps its whole per-output loop in a
	// try/catch and, when the loop admits zero outputs, THROWS ("This
	// transaction does not publish a valid ... descriptor!") — caught by
	// the outer catch, which returns `{coinsToRetain: [], outputsToAdmit:
	// []}`. Only when at least one output is admitted does it return
	// `{coinsToRetain: previousCoins, outputsToAdmit: outputs}`. So
	// canonical's real rule is: retain every previously-admitted coin only
	// when this tx admits at least one new output; a pure revocation
	// (zero new outputs, e.g. a spend with no replacement advert) retains
	// NONE of them, regardless of how many there are.
	//
	// The previous version of this topic always retained every previous
	// coin, admitted or not — so a revocation's spent coin was never
	// removed from the overlay engine's own storage (see the package doc
	// comment: separateRetainedCoins treats "not in CoinsToRetain" as
	// "delete"). Confirmed by direct engine-level reproduction: a
	// revocation's STEAK showed CoinsToRetain:[0] and the storage row
	// stayed "STILL STORED spent=true" forever under the old rule; under
	// this rule it shows CoinsToRetain empty and the row is deleted.
	var coinsToRetain []int
	if len(outputsToAdmit) > 0 {
		coinsToRetain = make([]int, len(previousUTXOs))
		for i := range previousUTXOs {
			coinsToRetain[i] = i
		}
	}

	if len(outputsToAdmit) == 0 && len(previousUTXOs) == 0 {
		// Truly nothing to do with this topic: no new output, and no
		// previously-admitted coin of ours for this tx to account for
		// either. (A pure revocation — outputsToAdmit empty but
		// previousUTXOs non-empty — falls through to the return below,
		// because the engine still needs real instructions to delete the
		// spent coin's storage row; see the package doc comment.)
		u.log.nothingAdmitted(UHRPTopicName)
		return nil, nil
	}

	// Divergence (flagged, not fixed in this brick): go-overlay-services'
	// SHIP/SLAP propagation gate (engine.go:697) only checks
	// OutputsToAdmit and CoinsToRetain, never CoinsRemoved — so a pure
	// revocation (both empty here) is never re-broadcast by this node to
	// the rest of the mesh, even though the engine does still correctly
	// delete the local storage row. The canonical TS engine's own gate
	// (Engine.ts's propagateSubmission, ~line 1040) additionally checks
	// `coinsRemoved?.length !== 0`, so canonical DOES re-propagate a pure
	// revocation. Anvil-side propagation is out of scope for this brick;
	// each node's own BRC-26 expiry check (uhrp_filter.go's uhrpExpired)
	// is the practical backstop — an un-propagated revocation still stops
	// resolving everywhere once its advertised expiry passes.
	return &overlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  coinsToRetain,
		CoinsRemoved:   nil,
		OutputMetadata: outputMetadata,
	}, nil
}

// GetDocumentation returns a description of the UHRP topic.
func (u *UHRPTopicManager) GetDocumentation() string {
	return "UHRP (BRC-26): Universal Hash Resolution Protocol. Tracks content availability advertisements — maps SHA-256 file hashes to hosting locations."
}

// GetMetadata returns machine-readable metadata about UHRP.
func (u *UHRPTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"brc":      26,
		"protocol": UHRPProtocolID,
		"purpose":  "content-availability-advertisement",
	}
}

// ParseUHRPOutput checks if a script is a UHRP advertisement, canonical
// BRC-26 PushDrop first, falling back to the legacy
// OP_FALSE OP_RETURN <"UHRP"> <sha256_hash> [<url>] [<content_type>]
// format. Returns nil for any script that is neither. This re-derives
// metadata from an output the caller already knows was admitted — it does
// NOT verify a BRC-26 output's signature (Admit does that once, at
// admission time); the single-value return keeps this a drop-in for its
// existing callers (the lookup service, legacyshim's metadata parser).
// Callers that want the malformed-vs-not-mine distinction, or BRC-26
// validation detail, for skip logging use classifyUHRPOutput /
// decodeUHRPBRC26 directly (Admit does).
func ParseUHRPOutput(script []byte) *UHRPEntry {
	if d, err := decodeUHRPBRC26(script); err == nil && d != nil {
		return d.toEntry()
	}
	entry, _ := classifyUHRPOutput(script)
	return entry
}

// classifyUHRPOutput, parsePushDataFields, HashContent, BuildUHRPScript and
// appendPushData (the legacy OP_RETURN format's decode/encode helpers) live
// in uhrp_legacy.go — split out to hold this file under the package's
// per-file size norm once the BRC-26 and fix-pass additions landed here
// (mirrors the lookups package's uhrp.go / uhrp_filter.go split), no
// behaviour change.

// Ensure UHRPTopicManager implements TopicManager at compile time.
var _ overlay.TopicManager = (*UHRPTopicManager)(nil)
