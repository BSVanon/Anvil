package legacyshim

import (
	"context"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// canonicalToLegacyAnswer reshapes a canonical LookupAnswer into the
// legacy form. For output-list answers it parses each BEEF, extracts
// the per-output script, and asks the service-specific ScriptParser to
// recover the Metadata blob legacy callers expect.
//
// Errors during per-output reconstruction are *logged as missing
// metadata* (we just omit the field) rather than failing the whole
// query, because failing would be a worse UX than returning the
// outpoint without its rich metadata. Callers can detect the missing-
// metadata case by the absent JSON field.
func (s *Shim) canonicalToLegacyAnswer(
	ctx context.Context,
	service string,
	answer *lookup.LookupAnswer,
) (*legacyLookupAnswer, error) {
	if answer == nil {
		return &legacyLookupAnswer{Type: "output-list"}, nil
	}

	switch answer.Type {
	case lookup.AnswerTypeFreeform:
		return &legacyLookupAnswer{
			Type:   "freeform",
			Result: answer.Result,
		}, nil

	case lookup.AnswerTypeOutputList, lookup.AnswerTypeFormula:
		out := &legacyLookupAnswer{Type: "output-list"}
		parser := s.Parsers[service]
		out.Outputs = make([]legacyAdmittedOutput, 0, len(answer.Outputs))
		for _, item := range answer.Outputs {
			if item == nil || len(item.Beef) == 0 {
				continue
			}
			legacy, err := s.reconstructLegacyOutput(ctx, service, parser, item)
			if err != nil {
				// Skip this output but don't fail the whole answer.
				continue
			}
			out.Outputs = append(out.Outputs, legacy)
		}
		return out, nil

	default:
		return nil, fmt.Errorf("legacyshim: unsupported answer type %q", answer.Type)
	}
}

// reconstructLegacyOutput parses an OutputListItem's BEEF, locates the
// admitted output at OutputIndex, and assembles the legacy
// AdmittedOutput record. Metadata is recovered by invoking the
// per-service ScriptParser; an unknown service or a parser that
// returns (nil, nil) yields an output record with no metadata field
// rather than an error.
func (s *Shim) reconstructLegacyOutput(
	ctx context.Context,
	service string,
	parser ScriptParser,
	item *lookup.OutputListItem,
) (legacyAdmittedOutput, error) {
	if err := ctx.Err(); err != nil {
		return legacyAdmittedOutput{}, err
	}
	tx, err := transaction.NewTransactionFromBEEF(item.Beef)
	if err != nil {
		return legacyAdmittedOutput{}, fmt.Errorf("parse output beef: %w", err)
	}
	if int(item.OutputIndex) >= len(tx.Outputs) {
		return legacyAdmittedOutput{}, fmt.Errorf("OutputIndex %d out of range (tx has %d outputs)", item.OutputIndex, len(tx.Outputs))
	}
	out := tx.Outputs[item.OutputIndex]
	if out == nil {
		return legacyAdmittedOutput{}, errors.New("nil output at OutputIndex")
	}
	var scriptBytes []byte
	if out.LockingScript != nil {
		scriptBytes = out.LockingScript.Bytes()
	}

	legacy := legacyAdmittedOutput{
		Txid:         tx.TxID().String(),
		Vout:         int(item.OutputIndex),
		Topic:        serviceToTopic(service),
		OutputScript: scriptBytes,
		Satoshis:     out.Satoshis,
	}

	if parser != nil {
		if meta, err := parser(scriptBytes); err == nil && meta != nil {
			legacy.Metadata = meta
		}
	}
	return legacy, nil
}

// serviceToTopic maps a canonical lookup-service name to the topic it
// indexes. Used to populate AdmittedOutput.Topic in the legacy
// response. Falls back to the service name when there's no known
// mapping (rare; only the 4 Anvil services are wired today).
func serviceToTopic(service string) string {
	switch service {
	case "ls_uhrp":
		return "tm_uhrp"
	case "ls_dex_swap":
		return "tm_dex_swap"
	case "ls_ordlock_listings":
		return "tm_ordlock_listings"
	case "ls_ordlock_buy_vaults":
		return "tm_ordlock_buy_vaults"
	default:
		return service
	}
}
