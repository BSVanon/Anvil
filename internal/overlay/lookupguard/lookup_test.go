package lookupguard

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

func TestOutputPageStopsBeforeRouteWireBudget(t *testing.T) {
	item := &lookup.OutputListItem{Beef: make([]byte, 2<<20)}
	source := make([]*lookup.OutputListItem, 5)
	for i := range source {
		source[i] = item
	}
	result, err := capOutputs(source, 0, true)
	if err != nil {
		t.Fatalf("cap outputs: %v", err)
	}
	if !result.Truncated || result.Next <= 0 || result.Next >= len(source) {
		t.Fatalf("pagination = truncated %v, next %d", result.Truncated, result.Next)
	}
	body, err := json.Marshal(result.Answer)
	if err != nil {
		t.Fatalf("marshal answer: %v", err)
	}
	if int64(len(body)) > routeguard.LookupAllowance {
		t.Fatalf("answer is %d bytes, cap is %d", len(body), routeguard.LookupAllowance)
	}
}

func TestOutputPageServesThreeMiBItem(t *testing.T) {
	item := &lookup.OutputListItem{Beef: make([]byte, 3<<20)}
	jsonResult, err := capOutputs([]*lookup.OutputListItem{item}, 0, true)
	if err != nil {
		t.Fatalf("cap JSON: %v", err)
	}
	if jsonResult.Truncated || len(jsonResult.Answer.Outputs) != 1 {
		t.Fatal("three MiB BEEF was removed from a JSON page")
	}
	if body, err := json.Marshal(jsonResult.Answer); err != nil || int64(len(body)) > routeguard.LookupAllowance {
		t.Fatalf("JSON answer did not fit the route cap: %v", err)
	}

	binaryResult, err := capOutputs([]*lookup.OutputListItem{item}, 0, false)
	if err != nil {
		t.Fatalf("cap binary: %v", err)
	}
	if binaryResult.Truncated || len(binaryResult.Answer.Outputs) != 1 {
		t.Fatal("three MiB BEEF was removed from a binary page")
	}
}

func TestOutputPageServesHonestSetWhole(t *testing.T) {
	source := make([]*lookup.OutputListItem, 4)
	for i := range source {
		source[i] = &lookup.OutputListItem{Beef: make([]byte, 1<<20), OutputIndex: uint32(i)}
	}
	result, err := capOutputs(source, 0, true)
	if err != nil {
		t.Fatalf("cap outputs: %v", err)
	}
	if result.Truncated || len(result.Answer.Outputs) != len(source) {
		t.Fatalf("page = truncated %v, outputs %d", result.Truncated, len(result.Answer.Outputs))
	}
}

func TestOutputPageCursorMakesProgress(t *testing.T) {
	source := make([]*lookup.OutputListItem, 5)
	for i := range source {
		source[i] = &lookup.OutputListItem{Beef: make([]byte, 2<<20), OutputIndex: uint32(i)}
	}

	cursor := 0
	seen := make([]uint32, 0, len(source))
	for {
		result, err := capOutputs(source, cursor, true)
		if err != nil {
			t.Fatalf("cap outputs: %v", err)
		}
		for _, output := range result.Answer.Outputs {
			seen = append(seen, output.OutputIndex)
		}
		if !result.Truncated {
			break
		}
		if result.Next <= cursor {
			t.Fatalf("cursor did not advance: request %d response %d", cursor, result.Next)
		}
		cursor = result.Next
	}
	for i, index := range seen {
		if index != uint32(i) {
			t.Fatalf("output %d = %d, want %d", i, index, i)
		}
	}
}

func TestOutputPageOmitsItemOverRouteAllowance(t *testing.T) {
	small := func(index uint32) *lookup.OutputListItem {
		return &lookup.OutputListItem{Beef: make([]byte, 2<<20), OutputIndex: index}
	}
	source := []*lookup.OutputListItem{small(0), {Beef: make([]byte, 7<<20), OutputIndex: 1}, small(2), small(3), small(4)}
	result, err := capOutputs(source, 0, true)
	if err != nil {
		t.Fatalf("cap outputs: %v", err)
	}
	if !result.Truncated || result.Next <= 0 || result.Omitted != 1 {
		t.Fatalf("page = truncated %v, next %d, omitted %d", result.Truncated, result.Next, result.Omitted)
	}
	if got := result.Answer.Outputs; len(got) != 2 || got[0].OutputIndex != 0 || got[1].OutputIndex != 2 {
		t.Fatalf("outputs = %#v", got)
	}
	rec := httptest.NewRecorder()
	WriteHeaders(rec, result)
	if got := rec.Header().Get(OmittedHeader); got != "1" {
		t.Fatalf("omitted header = %q", got)
	}
}

func TestOutputPageDoesNotTruncateWhenOnlyItemIsOmitted(t *testing.T) {
	result, err := capOutputs([]*lookup.OutputListItem{{Beef: make([]byte, 7<<20)}}, 0, true)
	if err != nil {
		t.Fatalf("cap outputs: %v", err)
	}
	if result.Truncated || result.Omitted != 1 || len(result.Answer.Outputs) != 0 {
		t.Fatalf("page = %#v", result)
	}
}

func TestPagerStopsDuringIndexIteration(t *testing.T) {
	pager := NewPager(t.Context())
	kept := 0
	for i := 0; i < peerhygiene.MaxLookupOutputs+1; i++ {
		take, stop := pager.Take()
		if take {
			kept++
		}
		if stop {
			break
		}
	}
	if kept != peerhygiene.MaxLookupOutputs {
		t.Fatalf("kept %d records, want %d", kept, peerhygiene.MaxLookupOutputs)
	}
}
