package v3engine

import (
	"reflect"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/lookupguard"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

func TestCapAggregatedAnswerBuildsLogarithmicPrefixes(t *testing.T) {
	tx := transaction.NewTransaction()
	tx.SetTxHash(&chainhash.Hash{})
	parse := parseAnswerBEEF
	parseAnswerBEEF = func([]byte) (*transaction.Transaction, error) { return tx, nil }
	t.Cleanup(func() { parseAnswerBEEF = parse })
	item := &lookup.OutputListItem{Beef: []byte{1}}
	outputs := make([]*lookup.OutputListItem, 10_000)
	for i := range outputs {
		outputs[i] = item
	}

	for _, tc := range []struct {
		name        string
		maximum     int
		wantOutputs int
		maximumRuns int
	}{
		{name: "fits", maximum: len(outputs), wantOutputs: len(outputs), maximumRuns: 1},
		{name: "overflows", maximum: len(outputs) / 2, wantOutputs: len(outputs) / 2, maximumRuns: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := buildAggregate
			runs := 0
			tooLarge := make([]byte, routeguard.LookupAllowance+1)
			buildAggregate = func(items []answerOutput) ([]byte, error) {
				if len(items) > 1 {
					runs++
				}
				if len(items) > tc.maximum {
					return tooLarge, nil
				}
				return []byte{0}, nil
			}
			t.Cleanup(func() { buildAggregate = original })

			result, err := capAggregatedAnswer(lookupguard.Result{Answer: outputListAnswer(outputs)}, 0)
			if err != nil {
				t.Fatalf("cap aggregated answer: %v", err)
			}
			if len(result.Answer.Outputs) != tc.wantOutputs {
				t.Fatalf("outputs = %d, want %d", len(result.Answer.Outputs), tc.wantOutputs)
			}
			if runs > tc.maximumRuns {
				t.Fatalf("whole-page aggregations = %d, want at most %d", runs, tc.maximumRuns)
			}
		})
	}
}

func TestCapAggregatedAnswerMatchesPrefixReference(t *testing.T) {
	output := func(size int, marker byte, index uint32) *lookup.OutputListItem {
		lockingScript := opReturn(size)
		(*lockingScript)[len(*lockingScript)-1] = marker
		tx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lockingScript, Satoshis: 1})
		return &lookup.OutputListItem{Beef: atomicBEEF(t, tx), OutputIndex: index}
	}
	result := lookupguard.Result{
		Answer: outputListAnswer([]*lookup.OutputListItem{
			output(1, 1, 0),
			output(9<<20, 2, 1),
			output(5<<20, 3, 2),
			output(4<<20, 4, 3),
			output(1, 5, 4),
		}),
	}

	want, err := capAggregatedAnswerReference(result, 23)
	if err != nil {
		t.Fatalf("reference cap: %v", err)
	}
	got, err := capAggregatedAnswer(result, 23)
	if err != nil {
		t.Fatalf("cap aggregated answer: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("page = %#v, want %#v", got, want)
	}
}

func capAggregatedAnswerReference(result lookupguard.Result, cursor int) (lookupguard.Result, error) {
	answer := result.Answer
	if answer == nil || answer.Type == lookup.AnswerTypeFreeform {
		return result, nil
	}
	outputs := make([]*lookup.OutputListItem, 0, len(answer.Outputs))
	omitted := result.Omitted
	for i, item := range answer.Outputs {
		alone, err := aggregatedAnswerSizeReference([]*lookup.OutputListItem{item})
		if err != nil {
			return lookupguard.Result{}, err
		}
		if alone > routeguard.LookupAllowance {
			omitted++
			continue
		}
		candidate := append(outputs, item)
		size, err := aggregatedAnswerSizeReference(candidate)
		if err != nil {
			return lookupguard.Result{}, err
		}
		if size > routeguard.LookupAllowance {
			return lookupguard.Result{
				Answer:    outputListAnswer(candidate[:len(candidate)-1]),
				Truncated: true,
				Next:      cursor + i,
				Omitted:   omitted,
			}, nil
		}
		outputs = candidate
	}
	if result.Truncated && len(outputs) > 0 {
		return lookupguard.Result{Answer: outputListAnswer(outputs), Truncated: true, Next: result.Next, Omitted: omitted}, nil
	}
	return lookupguard.Result{Answer: outputListAnswer(outputs), Omitted: omitted}, nil
}

func aggregatedAnswerSizeReference(outputs []*lookup.OutputListItem) (int64, error) {
	items := usableOutputs(outputs)
	payload, err := aggregateOutputs(items)
	if err == nil {
		return int64(len(payload)), nil
	}
	return perOutputAnswerSize(items), nil
}
