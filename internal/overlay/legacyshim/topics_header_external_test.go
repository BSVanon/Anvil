package legacyshim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// probeMaxDistinctTopics mirrors legacyshim's unexported maxDistinctTopics
// (internal/overlay/legacyshim/routes.go), which this black-box package
// cannot reference directly. Kept as its own named constant, not a bare
// literal, so a future change to the real cap has one obvious place here to
// update; legacyshim's own internal test (topics_header_test.go, package
// legacyshim) asserts the real constant's value directly.
const probeMaxDistinctTopics = 64

// countingManager counts calls to IdentifyAdmissibleOutputs, so a test can
// prove how many times admission actually ran for one submitted topic
// regardless of how many times that topic's name appeared in X-Topics.
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

// manyLegacyTopicsJSON returns the X-Topics JSON array of n distinct,
// deterministically named topics.
func manyLegacyTopicsJSON(n int) string {
	names := make([]string, n)
	for i := range names {
		names[i] = "tm_legacy_probe_" + strconv.Itoa(i)
	}
	raw, err := json.Marshal(names)
	if err != nil {
		panic(err) // unreachable: []string always marshals
	}
	return string(raw)
}

// TestLegacySubmit_DuplicateTopicsAdmittedOnce: POST /overlay/submit
// naming the same topic three times in X-Topics must run that topic's
// admission once, not three times — the same guard, and the same reason
// (routes.go's dedupTopics), as the canonical route's
// TestSubmitHandler_DuplicateTopicsAdmittedOnce.
func TestLegacySubmit_DuplicateTopicsAdmittedOnce(t *testing.T) {
	shim := newWiredShim(t)
	eng := shim.Engine.(*engine.Engine)
	const probeTopic = "tm_legacy_dedup_probe"
	var calls atomic.Int32
	eng.RegisterTopicManager(probeTopic, countingManager{calls: &calls, name: probeTopic})

	mux := http.NewServeMux()
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	const hashHex = "5555555555555555555555555555555555555555555555555555555555555555"
	beef := buildUHRPAtomicBEEF(t, hashHex)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/overlay/submit", bytes.NewReader(beef))
	req.Header.Set("Content-Type", "application/octet-stream")
	topicsJSON, _ := json.Marshal([]string{probeTopic, probeTopic, probeTopic})
	req.Header.Set("X-Topics", string(topicsJSON))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /overlay/submit: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, raw)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("IdentifyAdmissibleOutputs ran %d times for 3 copies of one topic, want 1", got)
	}

	var steak map[string]json.RawMessage
	if err := json.Unmarshal(raw, &steak); err != nil {
		t.Fatalf("decode steak: %v (raw=%s)", err, raw)
	}
	if len(steak) != 1 {
		t.Fatalf("steak has %d topics, want 1 (deduped): %s", len(steak), raw)
	}
	if _, ok := steak[probeTopic]; !ok {
		t.Fatalf("steak missing %q: %s", probeTopic, raw)
	}
}

// TestLegacySubmit_TooManyTopicsRejected: More than
// probeMaxDistinctTopics distinct topics in X-Topics is refused with 400
// before the engine ever sees the body's BEEF — dedupTopics runs ahead of
// preVerify in Shim.Submit.
func TestLegacySubmit_TooManyTopicsRejected(t *testing.T) {
	url := newShimServer(t)
	req, _ := http.NewRequest(http.MethodPost, url+"/overlay/submit", bytes.NewReader([]byte{0x00}))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", manyLegacyTopicsJSON(probeMaxDistinctTopics+1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /overlay/submit: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for %d distinct topics, got %d: %s", probeMaxDistinctTopics+1, resp.StatusCode, raw)
	}
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode legacy error envelope: %v (raw=%s)", err, raw)
	}
	if !strings.Contains(env["error"], "distinct topics") {
		t.Fatalf("error = %q, want it to mention \"distinct topics\"", env["error"])
	}
}
