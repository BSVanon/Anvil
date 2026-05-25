package topics

import (
	"context"
	"errors"
	"fmt"

	anvilov "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Adapter wraps an Anvil topic manager (overlay.TopicManager) and exposes it
// as a canonical engine.TopicManager. This is the W-2 bridge — Anvil's
// existing per-topic logic stays unchanged while the new engine consumes
// topics via the canonical interface.
//
// The translation handles four mechanical differences between the two
// interfaces:
//
//  1. Input shape: Anvil's Admit takes raw transaction bytes; the canonical
//     interface takes a *transaction.Beef + a *chainhash.Hash naming the tx
//     inside that BEEF. The adapter extracts the target tx and serialises it
//     back to bytes so the existing Anvil logic can keep using its parser.
//
//  2. Previous-input shape: Anvil's previousUTXOs is a positional slice with
//     rich AdmittedOutput data; the canonical previousCoins is just a list
//     of input indices (vins) that consume previously-admitted UTXOs for
//     this topic. The adapter feeds the Anvil topic a placeholder slice of
//     matching length — Anvil topics today only use the *count* of previous
//     UTXOs (via slice position), not the AdmittedOutput contents. Rich
//     ancestor data, when topics need it later, comes from the engine
//     calling Storage.FindOutputs.
//
//  3. Output index types: Anvil returns []int; canonical returns []uint32.
//     Straight type conversion.
//
//  4. Coin-index semantics: Anvil topics emit CoinsToRetain/CoinsRemoved as
//     slice-relative positions (0…len(previousUTXOs)-1). The canonical
//     contract expects actual transaction-input indices (vins). The adapter
//     remaps position → previousCoins[position] when materialising the
//     return value. With the placeholder slice produced by step 2 the
//     mapping is exactly one-to-one.
//
// OutputMetadata is intentionally dropped at the adapter boundary. Anvil's
// existing engine fed that metadata into the storage layer for lookup
// services to read back; the canonical model moves per-output metadata into
// each LookupService's own event-driven local state (handled in W-3).
type Adapter struct {
	name  string
	inner anvilov.TopicManager
	meta  *overlay.MetaData
	docs  string
}

// NewAdapter constructs an adapter for the given Anvil topic. name is the
// canonical topic identifier (e.g. "tm_uhrp"); meta provides the canonical
// metadata block returned by GetMetaData.
func NewAdapter(name string, inner anvilov.TopicManager, meta *overlay.MetaData) *Adapter {
	if inner == nil {
		panic("topics: NewAdapter with nil inner topic manager")
	}
	docs := inner.GetDocumentation()
	return &Adapter{name: name, inner: inner, meta: meta, docs: docs}
}

// Compile-time check.
var _ engine.TopicManager = (*Adapter)(nil)

// IdentifyAdmissibleOutputs is the canonical entry point. It pulls the
// target tx out of beef, hands it to the inner Anvil topic manager along
// with a placeholder previousUTXOs slice, then translates the result back
// into canonical AdmittanceInstructions.
func (a *Adapter) IdentifyAdmissibleOutputs(
	ctx context.Context,
	beef *transaction.Beef,
	txid *chainhash.Hash,
	previousCoins []uint32,
) (overlay.AdmittanceInstructions, error) {
	if err := ctx.Err(); err != nil {
		return overlay.AdmittanceInstructions{}, err
	}
	if beef == nil {
		return overlay.AdmittanceInstructions{}, fmt.Errorf("topic adapter %s: nil beef", a.name)
	}
	if txid == nil {
		return overlay.AdmittanceInstructions{}, fmt.Errorf("topic adapter %s: nil txid", a.name)
	}

	tx := beef.FindTransactionByHash(txid)
	if tx == nil {
		return overlay.AdmittanceInstructions{}, fmt.Errorf("topic adapter %s: tx %s: %w", a.name, txid.String(), ErrTxNotInBeef)
	}
	txBytes := tx.Bytes()

	prev := make([]anvilov.AdmittedOutput, len(previousCoins))
	inst, err := a.inner.Admit(txBytes, prev)
	if err != nil {
		return overlay.AdmittanceInstructions{}, fmt.Errorf("topic adapter %s: %w", a.name, err)
	}
	if inst == nil {
		return overlay.AdmittanceInstructions{}, nil
	}

	out := overlay.AdmittanceInstructions{
		OutputsToAdmit: intsToUint32(inst.OutputsToAdmit, len(tx.Outputs)),
		CoinsToRetain:  remapPositionsToVins(inst.CoinsToRetain, previousCoins),
		CoinsRemoved:   remapPositionsToVins(inst.CoinsRemoved, previousCoins),
	}
	return out, nil
}

// IdentifyNeededInputs reports ancestor outpoints the topic wants
// hydrated. None of Anvil's four topics need BRC-64 history walks today;
// returning (nil, nil) is the canonical "no extra inputs needed" answer.
func (a *Adapter) IdentifyNeededInputs(
	ctx context.Context,
	beef *transaction.Beef,
	txid *chainhash.Hash,
) ([]*transaction.Outpoint, error) {
	return nil, nil
}

// GetDocumentation is forwarded verbatim from the inner topic.
func (a *Adapter) GetDocumentation() string { return a.docs }

// GetMetaData returns the canonical metadata block. Anvil's
// GetMetadata() map[string]interface{} is not forwarded — its untyped shape
// can't satisfy the canonical *overlay.MetaData typed contract, so callers
// supply the typed metadata at construction time.
func (a *Adapter) GetMetaData() *overlay.MetaData { return a.meta }

// intsToUint32 converts a slice of admit-side output indices, dropping any
// negative or out-of-range entries defensively. txOutputCount is the number
// of outputs on the source tx; any index >= that is silently dropped to
// match how Anvil's engine guards the same range before writing to
// storage.
func intsToUint32(in []int, txOutputCount int) []uint32 {
	if len(in) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(in))
	for _, v := range in {
		if v < 0 || v >= txOutputCount {
			continue
		}
		out = append(out, uint32(v)) // #nosec G115 -- v is bounded [0, txOutputCount-1] by the guard above; txOutputCount fits in uint32 (Bitcoin tx output count is varint-bounded).
	}
	return out
}

// remapPositionsToVins translates slice-relative indices (Anvil convention,
// 0…len(previousUTXOs)-1) into actual transaction-input indices (canonical
// convention) by looking them up in previousCoins. Positions outside the
// slice are silently dropped.
func remapPositionsToVins(positions []int, previousCoins []uint32) []uint32 {
	if len(positions) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(positions))
	for _, p := range positions {
		if p < 0 || p >= len(previousCoins) {
			continue
		}
		out = append(out, previousCoins[p])
	}
	return out
}

// ErrTxNotInBeef is the sentinel returned when the requested txid is not
// present in the provided BEEF. The canonical engine guarantees the tx is
// always in the BEEF for the topics it routes; this sentinel exists so
// tests and tooling can detect the failure mode cleanly.
var ErrTxNotInBeef = errors.New("topic adapter: tx not in beef")
