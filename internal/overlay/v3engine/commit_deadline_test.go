package v3engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
)

// commitDeadline is the submit deadline in the engine-level mid-commit test.
// It only has to outlast the steps before the held one, which took 0.29 ms to
// 1.04 ms under -race (48 samples over 16 runs of the three cases, logged
// below as "held step began after"), so 500 ms leaves a margin of over 480
// times on a loaded machine. The held step then waits for the deadline
// itself, so the test does not depend on how long anything takes.
const commitDeadline = 500 * time.Millisecond

// TestSubmit_DeadlineMidCommitCompletesTheCommit: go-overlay-services v1.3.1's
// engine.Submit never checks its context between steps. Before the engine saw
// detached views of storage and lookup services, a deadline that expired
// during the commit stopped it at the next Anvil method that checked the
// context, so the submit failed and left durable partial state: an admitted
// input marked spent with nothing stored in its place, or one topic committed
// and the next not.
//
// Each case holds one commit step until the deadline has expired, under the
// context the legacy /overlay/submit shim builds: detached from the client,
// capped by a timeout, carrying the per-topic commit notifier. The shim's own
// handler is not driven here because its 30 s cap is a constant in routes.go.
// The submit must finish the commit in both topics, return the STEAK and
// signal both topics committed; the propagation that runs after the commit,
// under the expired context, must reach no tracker; and a resubmit must take
// the engine's duplicate path and change nothing.
func TestSubmit_DeadlineMidCommitCompletesTheCommit(t *testing.T) {
	cases := []struct{ name, method string }{
		{"after spend-marking", "MarkUTXOsAsSpent"},
		{"in the first InsertOutputs", "InsertOutputs"},
		{"in the first InsertAppliedTransaction", "InsertAppliedTransaction"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			se := newStallingEngine(t)
			tracker := newCountingTracker(t)
			se.eng.Advertiser = stubAdvertiser{}
			se.eng.SLAPTrackers = []string{tracker.URL}
			fx := newCommitFixture(t)
			admitOffer(t, se.eng, fx)
			if tracker.hits.Load() == 0 {
				t.Fatal("the offer's submit never queried the tracker, so a zero count later would prove nothing")
			}
			tracker.hits.Store(0)

			var committed []string
			ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), commitDeadline)
			defer cancel()
			ctx = overlayctx.WithTopicCommitNotifier(ctx, func(topic string) { committed = append(committed, topic) })
			start := time.Now()
			var heldAfter time.Duration
			heldLive := false
			se.stall.arm(c.method, func() {
				heldAfter, heldLive = time.Since(start), ctx.Err() == nil
				<-ctx.Done()
			})
			steakReady := false
			tagged := overlay.TaggedBEEF{Beef: fx.spendBEEF, Topics: commitTopics}
			steak, err := se.eng.Submit(ctx, tagged, engine.SubmitModeCurrent, func(*overlay.Steak) { steakReady = true })
			t.Logf("held step began after %v; submit returned after %v (deadline %v)", heldAfter, time.Since(start), commitDeadline)

			if !heldLive {
				t.Fatalf("%s was not held before the deadline: the case did not expire mid-commit", c.method)
			}
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("the deadline had not expired when the submit returned: %v", ctx.Err())
			}
			if err != nil {
				t.Errorf("the submit failed after its deadline expired mid-commit: %v", err)
			} else {
				assertSpendSteak(t, steak)
			}
			if !steakReady {
				t.Error("onSteakReady never ran")
			}
			if !slices.Equal(committed, commitTopics) {
				t.Errorf("the commit notifier saw %v, want %v", committed, commitTopics)
			}
			assertSpendCommitted(t, se, fx)
			if n := tracker.hits.Load(); n != 0 {
				t.Errorf("propagation ran under the expired deadline yet queried the tracker %d times", n)
			}
			if t.Failed() {
				return // a resubmit over partial state is not the duplicate path under test
			}
			assertResubmitIsADuplicate(t, se, tagged)
		})
	}
}

// assertSpendSteak fails unless steak admits the re-offer in tm_dex_swap and
// the advertisement in tm_uhrp.
func assertSpendSteak(t *testing.T, steak overlay.Steak) {
	t.Helper()
	want := map[string]uint32{topics.DEXSwapTopicName: 0, topics.UHRPTopicName: 2}
	for topic, vout := range want {
		if ai := steak[topic]; ai == nil || !slices.Equal(ai.OutputsToAdmit, []uint32{vout}) {
			t.Errorf("STEAK for %s: %+v, want vout %d admitted", topic, ai, vout)
		}
	}
}

// assertResubmitIsADuplicate resubmits tagged with no deadline and fails
// unless the engine answers on its duplicate path, admitting nothing, and the
// databases are unchanged.
func assertResubmitIsADuplicate(t *testing.T, se *stallingEngine, tagged overlay.TaggedBEEF) {
	t.Helper()
	before := stateDigest(t, se)
	steak, err := se.eng.Submit(context.Background(), tagged, engine.SubmitModeCurrent, nil)
	if err != nil {
		t.Fatalf("resubmit: %v", err)
	}
	for _, topic := range tagged.Topics {
		if ai := steak[topic]; ai == nil || len(ai.OutputsToAdmit) != 0 {
			t.Errorf("resubmit STEAK for %s: %+v, want the duplicate path's empty admittance", topic, ai)
		}
	}
	if after := stateDigest(t, se); after != before {
		t.Errorf("the resubmit changed state:\nbefore %s\nafter  %s", before, after)
	}
}

// handlerDeadline is Handlers.SubmitTimeout in the canonical-route test, and
// handlerOverrun is how far past it the held InsertOutputs runs. The hold
// starts after the handler has armed its deadline, so sleeping
// handlerDeadline plus any positive overrun from the hold's start crosses it;
// 250 ms is margin for timer and scheduler slack. The request reached
// InsertOutputs 0.69 ms to 1.18 ms after it was sent, under -race (5 runs,
// logged), far inside the 1 s deadline.
const (
	handlerDeadline = time.Second
	handlerOverrun  = 250 * time.Millisecond
)

// TestSubmitHandler_DeadlineMidCommitAnswers200: the same expiry through the
// canonical POST /submit, whose deadline is Handlers.SubmitTimeout. The commit
// finishes and engine.Submit returns the STEAK, so the route must answer 200
// with it, not 504. A resubmit must answer 200 on the duplicate path and
// change nothing.
func TestSubmitHandler_DeadlineMidCommitAnswers200(t *testing.T) {
	se := newStallingEngine(t)
	fx := newCommitFixture(t)
	admitOffer(t, se.eng, fx)

	h := NewHandlers(se.eng)
	h.SubmitTimeout = handlerDeadline
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	began := make(chan time.Time, 1)
	se.stall.arm("InsertOutputs", func() {
		began <- time.Now()
		time.Sleep(handlerDeadline + handlerOverrun)
	})
	start := time.Now()
	status, raw := postTopics(t, srv.URL, fx.spendBEEF, commitTopics)
	t.Logf("POST /submit answered %d after %v (deadline %v)", status, time.Since(start), handlerDeadline)
	select {
	case at := <-began:
		if lead := at.Sub(start); lead >= handlerDeadline {
			t.Fatalf("InsertOutputs began %v into the request, not before the %v deadline", lead, handlerDeadline)
		} else {
			t.Logf("held InsertOutputs began %v into the request", lead)
		}
	default:
		t.Fatal("the submit never reached InsertOutputs")
	}
	if status != http.StatusOK {
		t.Errorf("POST /submit answered %d after its deadline expired mid-commit: %s", status, raw)
	} else {
		assertWireSteak(t, raw, map[string][]uint32{topics.DEXSwapTopicName: {0}, topics.UHRPTopicName: {2}})
	}
	assertSpendCommitted(t, se, fx)
	if t.Failed() {
		return // a resubmit over partial state is not the duplicate path under test
	}

	before := stateDigest(t, se)
	status, raw = postTopics(t, srv.URL, fx.spendBEEF, commitTopics)
	if status != http.StatusOK {
		t.Fatalf("resubmit answered %d: %s", status, raw)
	}
	assertWireSteak(t, raw, map[string][]uint32{topics.DEXSwapTopicName: {}, topics.UHRPTopicName: {}})
	if after := stateDigest(t, se); after != before {
		t.Errorf("the resubmit changed state:\nbefore %s\nafter  %s", before, after)
	}
}

// postTopics POSTs body to /submit for topicList and returns the status code
// and response body.
func postTopics(t *testing.T, url string, body []byte, topicList []string) (int, []byte) {
	t.Helper()
	hdr, err := json.Marshal(topicList)
	if err != nil {
		t.Fatalf("marshal topics: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-topics", string(hdr))
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

// assertWireSteak fails unless the canonical STEAK JSON in raw admits exactly
// want's outputs for each of want's topics.
func assertWireSteak(t *testing.T, raw []byte, want map[string][]uint32) {
	t.Helper()
	var got map[string]topicAdmittance
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode STEAK %s: %v", raw, err)
	}
	for topic, outs := range want {
		if ai, ok := got[topic]; !ok || !slices.Equal(ai.OutputsToAdmit, outs) {
			t.Errorf("STEAK for %s: %+v, want outputsToAdmit %v", topic, ai, outs)
		}
	}
}
