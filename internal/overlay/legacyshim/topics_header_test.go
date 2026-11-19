package legacyshim

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

// TestDedupTopics_DedupesPreservingOrder: S5. The engine runs admission once
// per entry in the topics list it is handed, with no deduplication of its
// own, so /overlay/submit's X-Topics/JSON topic list must be collapsed
// before it reaches the engine, the same as the canonical route.
func TestDedupTopics_DedupesPreservingOrder(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"no duplicates", []string{"tm_a", "tm_b"}, []string{"tm_a", "tm_b"}},
		{"adjacent duplicate", []string{"tm_a", "tm_a", "tm_b"}, []string{"tm_a", "tm_b"}},
		{"duplicate keeps first position", []string{"tm_b", "tm_a", "tm_b", "tm_c", "tm_a"}, []string{"tm_b", "tm_a", "tm_c"}},
		{"all one topic", []string{"tm_a", "tm_a", "tm_a"}, []string{"tm_a"}},
		{"empty", []string{}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := dedupTopics(c.in)
			if err != nil {
				t.Fatalf("dedupTopics(%v): %v", c.in, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("dedupTopics(%v) = %v, want %v", c.in, got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("dedupTopics(%v) = %v, want %v", c.in, got, c.want)
				}
			}
		})
	}
}

// manyTopicNames returns n distinct, deterministically named topics.
func manyTopicNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = "tm_probe_" + strconv.Itoa(i)
	}
	return names
}

// TestDedupTopics_CapAtMaxDistinctTopics: S5. Exactly maxDistinctTopics
// distinct names is admitted; one more is refused, naming the count — the
// same bound as the canonical route's v3engine.maxDistinctTopics.
func TestDedupTopics_CapAtMaxDistinctTopics(t *testing.T) {
	if _, err := dedupTopics(manyTopicNames(maxDistinctTopics)); err != nil {
		t.Fatalf("%d distinct topics (the cap): %v", maxDistinctTopics, err)
	}
	_, err := dedupTopics(manyTopicNames(maxDistinctTopics + 1))
	if err == nil {
		t.Fatalf("%d distinct topics: want an error, got none", maxDistinctTopics+1)
	}
	want := fmt.Sprintf("more than %d distinct topics (%d named)", maxDistinctTopics, maxDistinctTopics+1)
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// keep encoding/json live for a clear compile error if this file's imports
// drift — manyTopicsJSON in the external test file covers the wire shape.
var _ = json.Marshal
