package v3engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestParseTopicsHeader_DedupesPreservingOrder: The engine runs admission
// once per entry in the topics list it is handed, with no deduplication of
// its own (go-overlay-services' identifyAdmissibleOutputsPerTopic ranges
// over the slice directly), so a repeated topic name must be collapsed
// before it gets there.
func TestParseTopicsHeader_DedupesPreservingOrder(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"no duplicates", []string{"tm_a", "tm_b"}, []string{"tm_a", "tm_b"}},
		{"adjacent duplicate", []string{"tm_a", "tm_a", "tm_b"}, []string{"tm_a", "tm_b"}},
		{"duplicate keeps first position", []string{"tm_b", "tm_a", "tm_b", "tm_c", "tm_a"}, []string{"tm_b", "tm_a", "tm_c"}},
		{"all one topic", []string{"tm_a", "tm_a", "tm_a"}, []string{"tm_a"}},
		{"empty", []string{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := json.Marshal(c.in)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}
			got, err := parseTopicsHeader(string(raw))
			if err != nil {
				t.Fatalf("parseTopicsHeader(%s): %v", raw, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("parseTopicsHeader(%s) = %v, want %v", raw, got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("parseTopicsHeader(%s) = %v, want %v", raw, got, c.want)
				}
			}
		})
	}
}

// manyTopicsJSON returns the JSON array of n distinct, deterministically
// named topics — used to probe the maxDistinctTopics cap from both the
// parseTopicsHeader unit and the full HTTP route.
func manyTopicsJSON(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = "tm_probe_" + strconv.Itoa(i)
	}
	raw, err := json.Marshal(names)
	if err != nil {
		panic(err) // unreachable: []string always marshals
	}
	return string(raw)
}

// TestParseTopicsHeader_CapAtMaxDistinctTopics: Exactly maxDistinctTopics
// distinct names is admitted; one more is refused, naming the count.
func TestParseTopicsHeader_CapAtMaxDistinctTopics(t *testing.T) {
	if _, err := parseTopicsHeader(manyTopicsJSON(maxDistinctTopics)); err != nil {
		t.Fatalf("%d distinct topics (the cap): %v", maxDistinctTopics, err)
	}
	_, err := parseTopicsHeader(manyTopicsJSON(maxDistinctTopics + 1))
	if err == nil {
		t.Fatalf("%d distinct topics: want an error, got none", maxDistinctTopics+1)
	}
	want := fmt.Sprintf("more than %d distinct topics (%d named)", maxDistinctTopics, maxDistinctTopics+1)
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// countingManager counts calls to IdentifyAdmissibleOutputs, so a test can
// prove how many times admission actually ran for one submitted topic
// regardless of how many times that topic's name appeared in x-topics.
type countingManager struct {
	calls *atomic.Int32
	name  string
}

func (m countingManager) IdentifyAdmissibleOutputs(context.Context, *transaction.Beef, *chainhash.Hash, []uint32) (overlay.AdmittanceInstructions, error) {
	m.calls.Add(1)
	return overlay.AdmittanceInstructions{OutputsToAdmit: []uint32{0}}, nil
}

func (countingManager) IdentifyNeededInputs(context.Context, *transaction.Beef, *chainhash.Hash) ([]*transaction.Outpoint, error) {
	return nil, nil
}

func (countingManager) GetDocumentation() string { return "" }
func (m countingManager) GetMetaData() *overlay.MetaData {
	return &overlay.MetaData{Name: m.name}
}

// TestSubmitHandler_DuplicateTopicsAdmittedOnce: POST /submit naming the
// same topic three times in x-topics must run that topic's admission once,
// not three times — the mutation this guards against is cheap to trigger
// (repeat one topic name) and expensive to leave unguarded (repeat the
// engine's admission work, and its DoesAppliedTransactionExist storage read,
// once per repeat).
func TestSubmitHandler_DuplicateTopicsAdmittedOnce(t *testing.T) {
	eng, _ := newTestEngine(t)
	const probeTopic = "tm_dedup_probe"
	var calls atomic.Int32
	eng.RegisterTopicManager(probeTopic, countingManager{calls: &calls, name: probeTopic})

	mux := http.NewServeMux()
	NewHandlers(eng).Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	lock := &script.Script{}
	_ = lock.AppendOpcodes(script.OpFALSE, script.OpRETURN)
	tx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 0})
	beef := encodeFixtureBEEF(t, tx, true)

	topicsJSON, _ := json.Marshal([]string{probeTopic, probeTopic, probeTopic})
	status, raw := postSubmitWithTopics(t, srv.URL, beef, string(topicsJSON))
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, raw)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("IdentifyAdmissibleOutputs ran %d times for 3 copies of one topic, want 1", got)
	}

	var steak overlay.Steak
	if err := json.Unmarshal(raw, &steak); err != nil {
		t.Fatalf("decode steak: %v", err)
	}
	if len(steak) != 1 {
		t.Fatalf("steak has %d topics, want 1 (deduped): %+v", len(steak), steak)
	}
}

// TestSubmitHandler_TooManyTopicsRejected: More than maxDistinctTopics
// distinct topics in x-topics is refused with 400 before the body is even
// read — the handler checks x-topics ahead of the body.
func TestSubmitHandler_TooManyTopicsRejected(t *testing.T) {
	url := newTestServer(t)
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", nil)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-topics", manyTopicsJSON(maxDistinctTopics+1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for %d distinct topics, got %d", maxDistinctTopics+1, resp.StatusCode)
	}
	assertCanonicalErrorEnvelope(t, resp.Body, "distinct topics")
}

// postSubmitWithTopics POSTs body to /submit with the given raw x-topics
// header JSON and returns the status code and response body.
func postSubmitWithTopics(t *testing.T, url string, body []byte, topicsJSON string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-topics", topicsJSON)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /submit response: %v", err)
	}
	return resp.StatusCode, raw
}
