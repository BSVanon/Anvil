package peerhygiene_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
)

// TestValidateLookupAnswer_RefusesEachReplyPastItsCap: hostiletest's reply
// past each per-answer cap is refused by that cap, and the costliest replies
// it builds are accepted, so the many-hosts tests that use them test what
// they say.
func TestValidateLookupAnswer_RefusesEachReplyPastItsCap(t *testing.T) {
	canary := hostiletest.NewCanary(t)
	parseCost := fmt.Sprintf(" bytes, over the %d-byte cap", peerhygiene.MaxBEEFParseCost)
	answerBEEF := fmt.Sprintf("BEEF exceeds capacity of %d bytes", peerhygiene.MaxAnswerBEEFBytes)
	want := map[string][2]string{ // the refusal's prefix and suffix
		"past-outputs": {fmt.Sprintf("binary lookup: the answer lists %d outputs, over the %d-output cap",
			4*peerhygiene.MaxLookupOutputs, peerhygiene.MaxLookupOutputs), ""},
		"past-parse-cost":      {"binary lookup: parsing the BEEF could cost ", parseCost},
		"past-answer-beef":     {"binary lookup: re-serialized " + answerBEEF, ""},
		"past-body":            {"peerhygiene: lookup response exceeds size cap: ", fmt.Sprintf("body is over %d bytes", peerhygiene.MaxLookupResponseBytes)},
		"past-json-cost":       {"lookup: decoding the JSON answer could cost ", fmt.Sprintf(" bytes, over the %d-byte cap", peerhygiene.MaxJSONDecodeCost)},
		"past-json-parse-cost": {"lookup: parsing output 1's BEEF could cost ", parseCost},
	}
	past := hostiletest.PastTheCaps(t, canary)
	if len(past) != len(want) {
		t.Fatalf("%d replies past the caps, want %d", len(past), len(want))
	}
	for _, r := range past {
		err := peerhygiene.ValidateLookupAnswer(r.ContentType, r.Bytes())
		w, ok := want[r.Name]
		if !ok {
			t.Errorf("unexpected reply %s", r.Name)
			continue
		}
		if err == nil || !strings.HasPrefix(err.Error(), w[0]) || !strings.HasSuffix(err.Error(), w[1]) {
			t.Errorf("%s: want a refusal %q...%q, got: %v", r.Name, w[0], w[1], err)
		}
	}
	for _, r := range hostiletest.Costliest(t, canary, 2) {
		if err := peerhygiene.ValidateLookupAnswer(r.ContentType, r.Bytes()); err != nil {
			t.Errorf("%s: the costliest reply must pass, got: %v", r.Name, err)
		}
	}
}
