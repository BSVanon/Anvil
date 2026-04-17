// DEX Swap topic manager for the Anvil overlay engine.
//
// Admits transaction outputs that represent swap offers:
//   Output N:   The offer UTXO (tokens or BSV locked to maker's key)
//   Output N+1: OP_FALSE OP_RETURN "dex.swap.offer" <version> <json_terms>
//
// When the offer UTXO is spent (accepted, revoked, or refund), the topic
// manager removes it from the active set via CoinsRemoved.
package topics

import (
	"encoding/json"
	"fmt"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// DEXSwapTopicName is the BRC-87 standard name for the DEX swap topic.
const DEXSwapTopicName = "tm_dex_swap"

// DEXSwapProtocol is the protocol prefix in the OP_RETURN metadata.
const DEXSwapProtocol = "dex.swap.offer"

// DEXSwapVersion is the current metadata format version.
const DEXSwapVersion = 1

// DEXSwapEntry is the metadata stored for each admitted swap offer.
type DEXSwapEntry struct {
	Maker      string          `json:"maker"`
	Offering   json.RawMessage `json:"offering"`
	Requesting json.RawMessage `json:"requesting"`
	RefundHeight int           `json:"refundHeight"`
	OfferVout  int             `json:"offerVout"`
}

// DEXSwapTopicManager implements overlay.TopicManager for DEX swap offers.
type DEXSwapTopicManager struct{}

// NewDEXSwapTopicManager creates a DEX swap topic manager.
func NewDEXSwapTopicManager() *DEXSwapTopicManager {
	return &DEXSwapTopicManager{}
}

// Admit evaluates a transaction for swap offer metadata outputs.
//
// Admission rules (enforced defensively against malformed or adversarial txs):
//  1. The metadata output must parse as `OP_FALSE OP_RETURN "dex.swap.offer"
//     <version> <json>` with a valid DEXSwapEntry body.
//  2. The referenced OfferVout must be adjacent to the metadata output at
//     `metadataVout - 1` — this enforces the documented Output N / Output N+1
//     protocol structure. Without it, a publisher could point the metadata
//     at any vout in the tx to pollute the topic index.
//  3. The referenced offer output must be spendable (not OP_RETURN or
//     OP_FALSE OP_RETURN). A non-spendable "offer" could never be taken,
//     so indexing it as an active offer is misleading to lookup consumers.
//  4. Only the first valid metadata output in a tx is processed — per-tx
//     multi-offer is out of scope for v1.
func (d *DEXSwapTopicManager) Admit(txData []byte, previousUTXOs []overlay.AdmittedOutput) (*overlay.AdmittanceInstructions, error) {
	tx, err := transaction.NewTransactionFromBytes(txData)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction: %w", err)
	}

	var outputsToAdmit []int
	var coinsRemoved []int
	outputMetadata := make(map[int]json.RawMessage)

	// Scan outputs for DEX swap offer metadata
	for metadataVout, out := range tx.Outputs {
		if out.LockingScript == nil {
			continue
		}

		entry := parseDEXSwapMetadata(out.LockingScript.Bytes())
		if entry == nil {
			continue
		}

		offerVout := entry.OfferVout

		// Rule 2: enforce documented Output N / Output N+1 adjacency.
		// The metadata must be the immediate successor of the offer.
		if offerVout != metadataVout-1 {
			continue
		}

		// Rule 3: the referenced offer must exist and be spendable.
		if offerVout < 0 || offerVout >= len(tx.Outputs) {
			continue
		}
		offerScript := tx.Outputs[offerVout].LockingScript
		if offerScript == nil || !isSpendableOffer(offerScript.Bytes()) {
			continue
		}

		// Admit ONLY the offer output — not the metadata OP_RETURN.
		// The metadata is stored as OutputMetadata on the offer output,
		// so the lookup service can access the swap terms without
		// admitting a separate output that would duplicate results.
		outputsToAdmit = append(outputsToAdmit, offerVout)

		meta, err := json.Marshal(entry)
		if err == nil {
			outputMetadata[offerVout] = meta
		}

		break // only process first metadata output per tx (rule 4)
	}

	// Mark previously-admitted offer UTXOs as spent
	for i := range previousUTXOs {
		coinsRemoved = append(coinsRemoved, i)
	}

	if len(outputsToAdmit) == 0 && len(coinsRemoved) == 0 {
		return nil, nil
	}

	return &overlay.AdmittanceInstructions{
		OutputsToAdmit: outputsToAdmit,
		CoinsToRetain:  nil,
		CoinsRemoved:   coinsRemoved,
		OutputMetadata: outputMetadata,
	}, nil
}

// isSpendableOffer returns true when a script is not an OP_RETURN (or safe
// OP_FALSE OP_RETURN) output. A non-spendable "offer" could never be taken,
// so admitting it would mislead lookup consumers.
func isSpendableOffer(script []byte) bool {
	if len(script) == 0 {
		return false
	}
	// Bare OP_RETURN (0x6a) at the start marks the output provably unspendable.
	if script[0] == 0x6a {
		return false
	}
	// OP_FALSE OP_RETURN (0x00 0x6a) is the safe-return pattern — also unspendable.
	if len(script) >= 2 && script[0] == 0x00 && script[1] == 0x6a {
		return false
	}
	return true
}

// GetDocumentation returns a description of the DEX swap topic.
func (d *DEXSwapTopicManager) GetDocumentation() string {
	return "DEX Swap Offers: Tracks active peer-to-peer token exchange offers. Offers are BRC-79 compatible atomic swaps with BRC-92 token support."
}

// GetMetadata returns machine-readable metadata about the DEX swap topic.
func (d *DEXSwapTopicManager) GetMetadata() map[string]interface{} {
	return map[string]interface{}{
		"protocol": DEXSwapProtocol,
		"version":  DEXSwapVersion,
		"purpose":  "swap-offer-tracking",
		"brcs":     []int{22, 79, 87, 92},
	}
}

// parseDEXSwapMetadata checks if a script is a DEX swap offer metadata output.
// Expected format: OP_FALSE OP_RETURN "dex.swap.offer" <version_byte> <json_terms>
func parseDEXSwapMetadata(script []byte) *DEXSwapEntry {
	if len(script) < 6 {
		return nil
	}

	// OP_FALSE (0x00) OP_RETURN (0x6a)
	if script[0] != 0x00 || script[1] != 0x6a {
		return nil
	}

	fields := parsePushDataFields(script[2:])
	if len(fields) < 3 {
		return nil
	}

	// Field 0: protocol prefix
	if string(fields[0]) != DEXSwapProtocol {
		return nil
	}

	// Field 1: version byte
	if len(fields[1]) != 1 || int(fields[1][0]) != DEXSwapVersion {
		return nil
	}

	// Field 2: JSON terms
	var entry DEXSwapEntry
	if err := json.Unmarshal(fields[2], &entry); err != nil {
		return nil
	}

	return &entry
}

// Ensure DEXSwapTopicManager implements TopicManager at compile time.
var _ overlay.TopicManager = (*DEXSwapTopicManager)(nil)
