package storage

import (
	"encoding/json"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// record is the on-disk shape stored under the ovl3 key family. It mirrors
// engine.Output minus the fields kept in their own key families
// (OutputsConsumed → txco3, ConsumedBy → cons3, AncillaryTxids → anci3,
// Beef → beef3). Keeping them out of the record lets each be updated in
// isolation without rewriting the output blob.
type record struct {
	// Outpoint is split into Txid hex + Index so the JSON stays
	// canonical-roundtrip-safe without depending on the Outpoint.String()
	// "<hex>.<idx>" convention.
	TxidHex      string          `json:"txid"`
	Index        uint32          `json:"index"`
	Topic        string          `json:"topic"`
	Spent        bool            `json:"spent,omitempty"`
	OutputScript []byte          `json:"outputScript,omitempty"`
	Satoshis     uint64          `json:"satoshis,omitempty"`
	BlockHeight  uint32          `json:"blockHeight,omitempty"`
	BlockIdx     uint64          `json:"blockIdx,omitempty"`
	Score        float64         `json:"score"`
	MerkleState  uint8           `json:"merkleState"`
	MerkleRoot   *chainhash.Hash `json:"merkleRoot,omitempty"`
	SpendingTxid *chainhash.Hash `json:"spendingTxid,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
}

// outpoint reconstructs a Outpoint from the record.
func (r *record) outpoint() *transaction.Outpoint {
	op := &transaction.Outpoint{Index: r.Index}
	// chainhash.NewHashFromHex always returns 32-byte hash; defensive copy.
	if h, err := chainhash.NewHashFromHex(r.TxidHex); err == nil {
		op.Txid = *h
	}
	return op
}

// toEngineOutput materializes a record into an engine.Output, leaving the
// ancillary slices (OutputsConsumed, ConsumedBy, AncillaryTxids, Beef) as
// nil — those are filled by the Storage method that owns the call (e.g.
// FindOutput hydrates them; FindUTXOsForTopic may skip BEEF when
// includeBEEF=false).
func (r *record) toEngineOutput() *engine.Output {
	op := r.outpoint()
	out := &engine.Output{
		Outpoint:    *op,
		Topic:       r.Topic,
		Spent:       r.Spent,
		BlockHeight: r.BlockHeight,
		BlockIdx:    r.BlockIdx,
		Score:       r.Score,
		MerkleState: engine.MerkleState(r.MerkleState),
		MerkleRoot:  r.MerkleRoot,
	}
	return out
}

func encodeRecord(r *record) ([]byte, error) {
	return json.Marshal(r)
}

func decodeRecord(b []byte) (*record, error) {
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
