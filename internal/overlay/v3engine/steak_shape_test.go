package v3engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay"
)

// TestCanonicalSteak_ShapeMatchesCanonicalWire locks the STEAK wire shape a dev
// reported: POST /submit was serializing the raw go-sdk overlay.Steak (no JSON
// tags) as PascalCase keys with null for empty slices
// ({"OutputsToAdmit":null,...}) — unparseable by a canonical @bsv/sdk client.
// It must be camelCase with empty arrays, never null.
func TestCanonicalSteak_ShapeMatchesCanonicalWire(t *testing.T) {
	// Empty admittance — the exact case the dev hit (nothing admitted → 200).
	b, err := json.Marshal(canonicalSteak(overlay.Steak{"tm_kvstore": &overlay.AdmittanceInstructions{}}))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{`"outputsToAdmit":[]`, `"coinsToRetain":[]`, `"coinsRemoved":[]`, `"ancillaryTxIDs":[]`} {
		if !strings.Contains(got, want) {
			t.Fatalf("canonical STEAK missing %s\n got: %s", want, got)
		}
	}
	for _, bad := range []string{"OutputsToAdmit", "ancillaryTxids", "null"} {
		if strings.Contains(got, bad) {
			t.Fatalf("canonical STEAK must not contain %q (PascalCase/null divergence)\n got: %s", bad, got)
		}
	}

	// Admitted outputs pass through under the camelCase key.
	b2, _ := json.Marshal(canonicalSteak(overlay.Steak{"tm_kvstore": &overlay.AdmittanceInstructions{OutputsToAdmit: []uint32{0, 2}}}))
	if !strings.Contains(string(b2), `"outputsToAdmit":[0,2]`) {
		t.Fatalf("admitted outputs not serialized correctly: %s", string(b2))
	}

	// A nil AdmittanceInstructions must still yield the full empty shape (no panic/null).
	b3, _ := json.Marshal(canonicalSteak(overlay.Steak{"tm_kvstore": nil}))
	if !strings.Contains(string(b3), `"outputsToAdmit":[]`) {
		t.Fatalf("nil admittance should yield empty arrays: %s", string(b3))
	}
}
