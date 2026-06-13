package legacyshim_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
)

// TestLegacySubmit_UnknownTopic_Returns400 is the regression for the
// DEX-reported overlay 500: submitting to a topic this node does not host must
// return 400 (client error), not a blanket 500 that looks like a node outage.
// The engine validates topics first, so this exercises the new
// statusForSubmitError mapping through the real shim+engine path.
func TestLegacySubmit_UnknownTopic_Returns400(t *testing.T) {
	url := newShimServer(t)
	const hashHex = "2222222222222222222222222222222222222222222222222222222222222222"
	beef := buildUHRPAtomicBEEF(t, hashHex)

	body, _ := json.Marshal(map[string]any{
		"beef":   beef,
		"topics": []string{"tm_this_topic_is_not_registered"},
	})
	resp, err := http.Post(url+"/overlay/submit", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown topic must be 400, got %d: %s", resp.StatusCode, raw)
	}
	// The body should carry the engine's "unknown-topic" reason, not an opaque 500.
	if !bytes.Contains(raw, []byte("unknown-topic")) {
		t.Errorf("expected unknown-topic reason in body, got: %s", raw)
	}
}

// TestLegacySubmit_ValidTopicStillSucceeds confirms the detached-goroutine +
// grace submit path (which keeps dead-peer propagation from hanging the
// response) does not regress the happy path: a fast valid submit completes
// within the grace window and returns 200 with the committed steak.
func TestLegacySubmit_ValidTopicStillSucceeds(t *testing.T) {
	url := newShimServer(t)
	const hashHex = "3333333333333333333333333333333333333333333333333333333333333333"
	beef := buildUHRPAtomicBEEF(t, hashHex)

	body, _ := json.Marshal(map[string]any{
		"beef":   beef,
		"topics": []string{topics.UHRPTopicName},
	})
	resp, err := http.Post(url+"/overlay/submit", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("valid submit must still be 200, got %d: %s", resp.StatusCode, raw)
	}
	var steak map[string]map[string][]int
	if err := json.NewDecoder(resp.Body).Decode(&steak); err != nil {
		t.Fatalf("decode steak: %v", err)
	}
	if _, ok := steak[topics.UHRPTopicName]; !ok {
		t.Fatalf("committed steak missing %q: %+v", topics.UHRPTopicName, steak)
	}
}

// TestLegacySubmit_Resubmit_StillSucceeds exercises the dupe/re-submit path
// end-to-end through the real shim+engine+storage — what a client retry after a
// slow response looks like. The second submit of the same (tx, topic) is a
// duplicate: the engine short-circuits via DoesAppliedTransactionExist, which
// fires the per-topic commit notifier so the handler still reaches full coverage
// and returns 200 (rather than hanging waiting for a commit signal that, for a
// dupe, never comes from InsertAppliedTransaction).
func TestLegacySubmit_Resubmit_StillSucceeds(t *testing.T) {
	url := newShimServer(t)
	const hashHex = "4444444444444444444444444444444444444444444444444444444444444444"
	beef := buildUHRPAtomicBEEF(t, hashHex)
	body, _ := json.Marshal(map[string]any{
		"beef":   beef,
		"topics": []string{topics.UHRPTopicName},
	})

	for attempt := 1; attempt <= 2; attempt++ {
		resp, err := http.Post(url+"/overlay/submit", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST attempt %d: %v", attempt, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("re-submit attempt %d must be 200, got %d: %s", attempt, resp.StatusCode, raw)
		}
		var steak map[string]map[string][]int
		if err := json.Unmarshal(raw, &steak); err != nil {
			t.Fatalf("attempt %d decode steak: %v (%s)", attempt, err, raw)
		}
		if _, ok := steak[topics.UHRPTopicName]; !ok {
			t.Fatalf("attempt %d steak missing %q: %s", attempt, topics.UHRPTopicName, raw)
		}
	}
}
