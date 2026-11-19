package legacyshim_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard"
	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// The submit chain is run with each stage near its limit.
const (
	// chainTopic's manager takes admitDelay to admit, so a submit spends
	// that long before it commits, as one whose verify is costly does.
	chainTopic = "tm_chain"
	admitDelay = 15 * time.Second
	// trackerDelay is how long the SLAP tracker takes to answer: just under
	// the 15 s the 30 s submit cap leaves after admitDelay, and well inside
	// the 30 s go-sdk itself allows a tracker query
	// (lookup.MAX_TRACKER_WAIT_TIME) and the whole SHIP query
	// (topic.MAX_SHIP_QUERY_TIMEOUT) — the submit cap, not go-sdk's own
	// allowance, is what binds now that the cap is 30 s.
	trackerDelay = 14500 * time.Millisecond
	// chainSlack allows for the work between the stages.
	chainSlack = 3 * time.Second
	// chainWait is how long the measurement waits for the legacy route's
	// background propagation: past go-sdk's own 15 + 30 + 30 s chain.
	chainWait = 90 * time.Second
)

// chainManager admits a transaction's first output after admitDelay.
type chainManager struct{}

func (chainManager) IdentifyAdmissibleOutputs(context.Context, *transaction.Beef, *chainhash.Hash, []uint32) (overlay.AdmittanceInstructions, error) {
	time.Sleep(admitDelay)
	return overlay.AdmittanceInstructions{OutputsToAdmit: []uint32{0}}, nil
}

func (chainManager) IdentifyNeededInputs(context.Context, *transaction.Beef, *chainhash.Hash) ([]*transaction.Outpoint, error) {
	return nil, nil
}

func (chainManager) GetDocumentation() string       { return "" }
func (chainManager) GetMetaData() *overlay.MetaData { return &overlay.MetaData{Name: chainTopic} }

// TestSubmitChain_WorstCase measures how long each submit route takes when
// every stage of its chain runs to its limit: admission takes 15 s; the SLAP
// tracker the propagation asks for SHIP hosts answers at 14.5 s, inside both
// go-sdk's 30 s tracker allowance and the 15 s the 30 s submit cap leaves
// after admitDelay; and the one SHIP host it names trickles its STEAK reply
// faster than the guard's rate floor, forever. The canonical POST /submit
// answers once its propagation ends, so it must answer by the submit cap
// (30 s) plus netguard.SubmitTimeout (15 s), 45 s; the legacy POST
// /overlay/submit answers at commit, and its background propagation must end
// by the same bound. With go-sdk's 30 s per send instead of netguard's 15 s,
// both took 60 s.
//
// It takes about a minute, so it runs only with ANVIL_MEASURE_SUBMIT_CHAIN
// set.
func TestSubmitChain_WorstCase(t *testing.T) {
	if os.Getenv("ANVIL_MEASURE_SUBMIT_CHAIN") == "" {
		t.Skip("set ANVIL_MEASURE_SUBMIT_CHAIN=1 to measure the submit chain; it takes about a minute")
	}
	logs := hostiletest.WatchLogs(t)
	opening := hostiletest.Literal("opening", []byte(`{"`+chainTopic+`":{"outputsToAdmit":[`))
	peer := hostiletest.NewSteakPeer(t, chainTopic, hostiletest.SteakReply{Body: opening, Rate: 50_000})
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-time.After(trackerDelay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(hostiletest.SLAPAnswer(peer.URL))
	}))
	t.Cleanup(tracker.Close)

	bound := v3engine.DefaultSubmitTimeout + netguard.SubmitTimeout
	floor := admitDelay + trackerDelay + netguard.SubmitTimeout
	if floor > bound || trackerDelay >= lookup.MAX_TRACKER_WAIT_TIME {
		t.Fatalf("the stages (%v) must fit the bound (%v) and go-sdk's tracker wait", floor, bound)
	}

	canonicalURL, canonicalBEEF, _ := chainNode(t, tracker.URL, 0)
	legacyURL, legacyBEEF, legacyTxid := chainNode(t, tracker.URL, 1)
	var wg sync.WaitGroup
	var canonical, legacyReply, legacyEnd time.Duration
	var canonicalErr, legacyErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		start := time.Now()
		canonicalErr = postBEEF(canonicalURL+"/submit", canonicalBEEF)
		canonical = time.Since(start)
	}()
	go func() {
		defer wg.Done()
		start := time.Now()
		if legacyErr = postBEEF(legacyURL+"/overlay/submit", legacyBEEF); legacyErr != nil {
			return
		}
		legacyReply = time.Since(start)
		// Wait well past the bound, so a chain that overruns it is measured.
		if logs.Line(chainWait-legacyReply, failedPropagation, legacyTxid) == "" {
			legacyErr = fmt.Errorf("the background propagation did not end within %v", chainWait)
		}
		legacyEnd = time.Since(start)
	}()
	wg.Wait()
	t.Logf("canonical /submit answered after %v; legacy /overlay/submit answered after %v and its propagation ended after %v (stages %v, bound %v)",
		canonical.Round(time.Millisecond), legacyReply.Round(time.Millisecond), legacyEnd.Round(time.Millisecond), floor, bound)
	if canonicalErr != nil || legacyErr != nil {
		t.Fatalf("canonical: %v; legacy: %v", canonicalErr, legacyErr)
	}
	for name, took := range map[string]time.Duration{"the canonical submit": canonical, "the legacy propagation": legacyEnd} {
		if took < floor-chainSlack || took > bound+chainSlack {
			t.Errorf("%s took %v, want the %v the stages take, within the %v bound", name, took, floor, bound)
		}
	}
	if legacyReply > admitDelay+chainSlack {
		t.Errorf("the legacy submit answered after %v, want at its commit, about %v", legacyReply, admitDelay)
	}
}

// chainNode is a node whose engine hosts chainTopic and asks tracker for SHIP
// hosts, serving both submit routes, with a fresh transaction for it.
func chainNode(t *testing.T, tracker string, i int) (url string, beef []byte, txid string) {
	t.Helper()
	shim := newWiredShim(t)
	eng := shim.Engine.(*engine.Engine)
	eng.RegisterTopicManager(chainTopic, chainManager{})
	eng.Advertiser = &steakAdvertiser{}
	eng.SLAPTrackers = []string{tracker}
	mux := http.NewServeMux()
	v3engine.NewHandlers(eng).Register(mux, nil)
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	beef = buildUHRPAtomicBEEF(t, fmt.Sprintf("%064x", 0xc4a10+i))
	_, id, err := transaction.NewBeefFromAtomicBytes(beef)
	if err != nil {
		t.Fatalf("NewBeefFromAtomicBytes: %v", err)
	}
	return srv.URL, beef, id.String()
}

// postBEEF submits beef to chainTopic at url on a client of its own: the
// guard on http.DefaultClient would end the test's own exchange at its
// submit timeout.
func postBEEF(url string, beef []byte) error {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(beef))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", `["`+chainTopic+`"]`)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d: %s", url, resp.StatusCode, body)
	}
	return nil
}
