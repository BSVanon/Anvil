package legacyshim

import (
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/lookupguard"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
)

func TestLegacyLookupAnswerReportsBoundedPage(t *testing.T) {
	outputs := make([]legacyAdmittedOutput, 100)
	for i := range outputs {
		outputs[i].OutputScript = make([]byte, 64<<10)
	}
	answer := &legacyLookupAnswer{Type: "output-list", Outputs: outputs}
	result := lookupguard.Result{}
	body, err := capLegacyAnswer(answer, &result, 20)
	if err != nil {
		t.Fatalf("cap legacy answer: %v", err)
	}
	if int64(len(body)) > routeguard.LookupAllowance {
		t.Fatalf("answer is %d bytes, cap is %d", len(body), routeguard.LookupAllowance)
	}
	if !result.Truncated || result.Next != 20+len(answer.Outputs) {
		t.Fatalf("pagination = truncated %v, next %d, outputs %d", result.Truncated, result.Next, len(answer.Outputs))
	}
}

func TestLegacyLookupAnswerServesHonestSetWhole(t *testing.T) {
	outputs := make([]legacyAdmittedOutput, 50)
	for i := range outputs {
		outputs[i].OutputScript = make([]byte, 64<<10)
	}
	answer := &legacyLookupAnswer{Type: "output-list", Outputs: outputs}
	result := lookupguard.Result{}
	body, err := capLegacyAnswer(answer, &result, 0)
	if err != nil {
		t.Fatalf("cap legacy answer: %v", err)
	}
	if result.Truncated || len(answer.Outputs) != len(outputs) {
		t.Fatalf("page = truncated %v, outputs %d", result.Truncated, len(answer.Outputs))
	}
	if int64(len(body)) > routeguard.LookupAllowance {
		t.Fatalf("answer is %d bytes, cap is %d", len(body), routeguard.LookupAllowance)
	}
}

func TestLegacyLookupAnswerOmitsOversizedOutput(t *testing.T) {
	answer := &legacyLookupAnswer{Type: "output-list", Outputs: []legacyAdmittedOutput{
		{OutputScript: make([]byte, 7<<20)},
		{OutputScript: make([]byte, 1<<20)},
	}}
	result := lookupguard.Result{}
	body, err := capLegacyAnswer(answer, &result, 0)
	if err != nil {
		t.Fatalf("cap legacy answer: %v", err)
	}
	if result.Truncated || result.Omitted != 1 || len(answer.Outputs) != 1 {
		t.Fatalf("page = %#v, outputs %d", result, len(answer.Outputs))
	}
	if int64(len(body)) > routeguard.LookupAllowance {
		t.Fatalf("answer is %d bytes, cap is %d", len(body), routeguard.LookupAllowance)
	}
}
