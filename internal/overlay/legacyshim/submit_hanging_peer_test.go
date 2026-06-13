package legacyshim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"

	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
)

// scriptedEngine drives the exact engine ordering the shim depends on:
// onSteakReady (pre-commit) → a per-topic durable-commit signal for each topic
// in commitTopics (overlayctx, as the real Storage fires per topic) → optional
// error / hung propagation. Lets the submit handler be tested for the contracts
// Codex flagged across iterations: never ack before EVERY submitted topic is
// durably committed, and don't hang on dead-peer propagation.
type scriptedEngine struct {
	steak        overlay.Steak
	commitTopics []string      // topics that durably commit (fire the notifier), in order
	submitErr    error         // returned after the commit signals (e.g. a later topic failed)
	release      chan struct{} // if non-nil, block (hung propagation) until closed or ctx done
	propagating  chan struct{} // if non-nil, signalled once propagation is reached
}

func (e *scriptedEngine) Submit(ctx context.Context, _ overlay.TaggedBEEF, _ engine.SumbitMode, onReady engine.OnSteakReady) (overlay.Steak, error) {
	if onReady != nil {
		onReady(&e.steak) // admission identified outputs for all topics (pre-commit)
	}
	for _, t := range e.commitTopics {
		overlayctx.NotifyTopicCommitted(ctx, t) // per-topic durable commit, as InsertAppliedTransaction does
	}
	if e.submitErr != nil {
		return nil, e.submitErr // e.g. a later topic's commit failed after an earlier one committed
	}
	if e.propagating != nil {
		select {
		case e.propagating <- struct{}{}:
		default:
		}
	}
	if e.release != nil {
		select { // simulate hung cross-node propagation
		case <-e.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return e.steak, nil
}

func (e *scriptedEngine) Lookup(context.Context, *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	return nil, nil
}
func (e *scriptedEngine) ListTopicManagers() map[string]*overlay.MetaData          { return nil }
func (e *scriptedEngine) ListLookupServiceProviders() map[string]*overlay.MetaData { return nil }

func submitReq(topics ...string) (*http.Request, *httptest.ResponseRecorder) {
	body, _ := json.Marshal(map[string]any{"beef": []byte{0x01, 0x02}, "topics": topics})
	req := httptest.NewRequest("POST", "/overlay/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req, httptest.NewRecorder()
}

func admit(vout uint32) *overlay.AdmittanceInstructions {
	return &overlay.AdmittanceInstructions{OutputsToAdmit: []uint32{vout}}
}

// TestSubmit_HangingPeer_RespondsAfterCommit is the regression for Codex's first
// High: /overlay/submit must return promptly even when cross-node propagation
// hangs (it can't be bounded by our context). The single topic commits, then
// propagation blocks — the handler must return 200 with the admittance steak
// without waiting for propagation.
func TestSubmit_HangingPeer_RespondsAfterCommit(t *testing.T) {
	eng := &scriptedEngine{
		steak:        overlay.Steak{"tm_dex_swap": admit(0)},
		commitTopics: []string{"tm_dex_swap"},
		release:      make(chan struct{}),
		propagating:  make(chan struct{}, 1),
	}
	defer close(eng.release)
	shim := &Shim{Engine: eng, Parsers: DefaultParsers(), ServiceTopics: DefaultServiceTopics()}

	req, w := submitReq("tm_dex_swap")
	start := time.Now()
	shim.Submit(w, req)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("Submit blocked %v on a hanging peer — must return once committed", elapsed)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after durable commit, got %d: %s", w.Code, w.Body.String())
	}
	var got map[string]map[string][]int
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode steak: %v (%s)", err, w.Body.String())
	}
	if inst, ok := got["tm_dex_swap"]; !ok || len(inst["outputsToAdmit"]) != 1 {
		t.Fatalf("response must carry the admission steak, got: %s", w.Body.String())
	}
	select {
	case <-eng.propagating:
	case <-time.After(time.Second):
		t.Error("engine never reached propagation")
	}
}

// TestSubmit_CommitFailure_DoesNotAckSuccess is the regression for Codex's
// second High: if commit fails (the notifier never fires and the engine returns
// an error), /overlay/submit must surface the error — NOT a premature 200.
func TestSubmit_CommitFailure_DoesNotAckSuccess(t *testing.T) {
	eng := &scriptedEngine{
		steak:        overlay.Steak{"tm_dex_swap": admit(0)},
		commitTopics: nil, // commit did not complete → notifier never fires
		submitErr:    errors.New("storage: insert outputs failed"),
	}
	shim := &Shim{Engine: eng, Parsers: DefaultParsers(), ServiceTopics: DefaultServiceTopics()}

	req, w := submitReq("tm_dex_swap")
	shim.Submit(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("commit failure must NOT return 200; body: %s", w.Body.String())
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("commit failure should be 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSubmit_MultiTopic_PartialCommit_DoesNotAck is the regression for Codex's
// THIRD High: a multi-topic submit where topic A commits and topic B fails
// afterward must NOT return 200 + a full steak. Only tm_a signals; the engine
// then errors (tm_b failed). The handler must wait for ALL submitted topics and
// surface the error instead of acking on the first commit.
func TestSubmit_MultiTopic_PartialCommit_DoesNotAck(t *testing.T) {
	eng := &scriptedEngine{
		steak:        overlay.Steak{"tm_a": admit(0), "tm_b": admit(1)},
		commitTopics: []string{"tm_a"}, // tm_a durably commits; tm_b never does
		submitErr:    errors.New("storage: insert outputs failed for tm_b"),
	}
	shim := &Shim{Engine: eng, Parsers: DefaultParsers(), ServiceTopics: DefaultServiceTopics()}

	req, w := submitReq("tm_a", "tm_b")
	shim.Submit(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("partial multi-topic commit must NOT return 200; body: %s", w.Body.String())
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("partial commit should surface the engine error as 500, got %d: %s", w.Code, w.Body.String())
	}
}

// TestSubmit_MultiTopic_AllCommit_RespondsAfterAll proves the happy multi-topic
// path: once BOTH topics are durably committed the handler returns 200 with the
// full steak, without waiting for hung cross-node propagation.
func TestSubmit_MultiTopic_AllCommit_RespondsAfterAll(t *testing.T) {
	eng := &scriptedEngine{
		steak:        overlay.Steak{"tm_a": admit(0), "tm_b": admit(1)},
		commitTopics: []string{"tm_a", "tm_b"},
		release:      make(chan struct{}),
		propagating:  make(chan struct{}, 1),
	}
	defer close(eng.release)
	shim := &Shim{Engine: eng, Parsers: DefaultParsers(), ServiceTopics: DefaultServiceTopics()}

	req, w := submitReq("tm_a", "tm_b")
	start := time.Now()
	shim.Submit(w, req)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("Submit blocked %v on a hanging peer — must return once all topics committed", elapsed)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after all topics committed, got %d: %s", w.Code, w.Body.String())
	}
	var got map[string]map[string][]int
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode steak: %v (%s)", err, w.Body.String())
	}
	for _, topic := range []string{"tm_a", "tm_b"} {
		if inst, ok := got[topic]; !ok || len(inst["outputsToAdmit"]) != 1 {
			t.Fatalf("response must carry the full multi-topic steak; missing %s in: %s", topic, w.Body.String())
		}
	}
	select {
	case <-eng.propagating:
	case <-time.After(time.Second):
		t.Error("engine never reached propagation")
	}
}
