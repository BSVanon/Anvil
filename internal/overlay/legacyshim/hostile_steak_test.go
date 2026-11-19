package legacyshim_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard"
	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// failedPropagation is what go-overlay-services' engine logs, with the txid,
// when no SHIP host acknowledged a transaction it propagated.
const failedPropagation = "failed to propagate transaction to other nodes"

// outcomeSlack is how much later than its cause a failed propagation may be
// logged on a loaded test machine.
const outcomeSlack = 5 * time.Second

// oversizeHeapLimit bounds the heap a run with a 64 MiB reply may allocate:
// three times the 1 MiB netguard.MaxSteakBytes, for the read buffer as it
// doubles up to the cap, and hostiletest.HeapMargin for the engine and the
// servers. It is written out, not derived from the cap, so that raising the
// cap fails here until the budget is redone.
const oversizeHeapLimit = 3<<20 + hostiletest.HeapMargin

// steakAdvertiser is the engine's Advertiser. go-overlay-services propagates
// an admitted submit only when the engine has one, and SyncAdvertisements
// submits, and so propagates, whatever CreateAdvertisements returns: here a
// UHRP transaction, which the engine admits as it admits a SHIP advertisement.
type steakAdvertiser struct {
	tagged  overlay.TaggedBEEF
	created atomic.Int64
}

func (a *steakAdvertiser) CreateAdvertisements([]*advertiser.AdvertisementData) (overlay.TaggedBEEF, error) {
	a.created.Add(1)
	return a.tagged, nil
}

func (*steakAdvertiser) FindAllAdvertisements(overlay.Protocol) ([]*advertiser.Advertisement, error) {
	return nil, nil
}

func (*steakAdvertiser) RevokeAdvertisements([]*advertiser.Advertisement) (overlay.TaggedBEEF, error) {
	return overlay.TaggedBEEF{}, errors.New("nothing to revoke")
}

func (*steakAdvertiser) ParseAdvertisement(*script.Script) (*advertiser.Advertisement, error) {
	return nil, errors.New("nothing to parse")
}

// steakRun is one case wired up: a peer giving the case's reply, and a shim
// whose engine finds that peer, through its only SLAP tracker, as the one
// SHIP host for tm_uhrp, with a fresh UHRP transaction to propagate to it.
type steakRun struct {
	peer *hostiletest.SteakPeer
	eng  *engine.Engine
	adv  *steakAdvertiser
	url  string // the shim's server
	beef []byte // the transaction's Atomic BEEF
	txid string
}

func newSteakRun(t *testing.T, c hostiletest.SteakCase, i int) *steakRun {
	t.Helper()
	r := &steakRun{peer: hostiletest.NewSteakPeer(t, topics.UHRPTopicName, c.Reply)}
	shim := newWiredShim(t)
	r.eng = shim.Engine.(*engine.Engine)
	r.beef = buildUHRPAtomicBEEF(t, fmt.Sprintf("%064x", 0x57ea0+i))
	_, txid, err := transaction.NewBeefFromAtomicBytes(r.beef)
	if err != nil {
		t.Fatalf("NewBeefFromAtomicBytes: %v", err)
	}
	r.txid = txid.String()
	r.adv = &steakAdvertiser{tagged: overlay.TaggedBEEF{Beef: r.beef, Topics: []string{topics.UHRPTopicName}}}
	r.eng.Advertiser = r.adv
	r.eng.SLAPTrackers = []string{r.peer.URL}
	mux := http.NewServeMux()
	shim.Register(mux, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r.url = srv.URL
	return r
}

// outcome is what the engine made of one case's reply.
type outcome struct {
	line string        // the engine's failed-propagation line for the transaction, if it logged one
	took time.Duration // from the submit to that line, or to the peer being done
	err  error         // a failure of the submit itself
}

// legacySubmit posts the transaction to POST /overlay/submit, which answers
// at commit and propagates in the background, and waits for the outcome.
func (r *steakRun) legacySubmit(c hostiletest.SteakCase, logs *hostiletest.Logs) outcome {
	start := time.Now()
	req, err := http.NewRequest(http.MethodPost, r.url+"/overlay/submit", bytes.NewReader(r.beef))
	if err != nil {
		return outcome{err: err}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", `["`+topics.UHRPTopicName+`"]`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return outcome{err: fmt.Errorf("the legacy submit failed: %w", err)}
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return outcome{err: fmt.Errorf("the legacy submit answered %d: %s", resp.StatusCode, body)}
	}
	if c.Accepted {
		// The engine logs nothing when a propagation succeeds, so give it
		// time to fail once the peer has answered.
		waitFor(10*time.Second, func() bool { return r.peer.Submits() > 0 && r.peer.Writing() == 0 })
		time.Sleep(300 * time.Millisecond)
		return outcome{line: logs.Line(0, failedPropagation, r.txid), took: time.Since(start)}
	}
	_, to := window(c)
	line := logs.Line(time.Until(start.Add(to)), failedPropagation, r.txid)
	return outcome{line: line, took: time.Since(start)}
}

// syncAdvertisements runs the engine's advertisement sync, which submits and
// propagates the advertiser's transaction before it returns.
func (r *steakRun) syncAdvertisements(logs *hostiletest.Logs) outcome {
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- r.eng.SyncAdvertisements(context.Background()) }()
	select {
	case err := <-done:
		if err == nil && r.adv.created.Load() != 1 {
			err = errors.New("the sync created no advertisement, so it propagated nothing")
		}
		return outcome{line: logs.Line(0, failedPropagation, r.txid), took: time.Since(start), err: err}
	case <-time.After(60 * time.Second):
		return outcome{err: errors.New("SyncAdvertisements did not return within 60s")}
	}
}

// window is when, after the submit, the propagation of a reply the guard
// refuses must fail: at once for a complete reply, at the rate floor's grace
// for a reply that trickles below the floor, and at the exchange timeout for
// one that trickles above it.
func window(c hostiletest.SteakCase) (from, to time.Duration) {
	switch {
	case c.Reply.Rate > 0 && c.Reply.Rate < bodyread.MinReadRate:
		return bodyread.ReadGrace, bodyread.ReadGrace + outcomeSlack
	case c.Reply.Rate > 0:
		return netguard.SubmitTimeout, netguard.SubmitTimeout + outcomeSlack
	default:
		return 0, outcomeSlack
	}
}

// check asserts what the guarded engine made of the case's reply: the
// propagation reached the peer and failed, within the case's window, unless
// the guard had to accept the reply; the peer was let go of; a run with an
// oversize reply allocated, and so held, within three times the STEAK cap and
// a margin; and the run kept no memory.
func (r *steakRun) check(t *testing.T, c hostiletest.SteakCase, o outcome, m measured) {
	t.Helper()
	if o.err != nil {
		t.Fatal(o.err)
	}
	if r.peer.Submits() == 0 {
		t.Fatal("the propagation never reached the peer, so the case tests nothing")
	}
	from, to := window(c)
	switch {
	case c.Accepted && o.line != "":
		t.Fatalf("the guard must hand this reply on, but the propagation failed: %s", o.line)
	case !c.Accepted && o.line == "":
		t.Fatalf("the propagation must fail for this reply, and nothing was logged for %v", o.took)
	case !c.Accepted && (o.took < from || o.took > to):
		t.Fatalf("the propagation failed after %v, want %v to %v", o.took, from, to)
	}
	if !waitFor(5*time.Second, func() bool { return r.peer.Writing() == 0 }) {
		t.Fatal("the peer is still writing its reply: nothing let go of it")
	}
	if c.Oversize && max(m.peak, m.allocated) > oversizeHeapLimit {
		t.Fatalf("the run allocated %.1f MiB and its heap peaked %.1f MiB higher, over %d MiB", mib(m.allocated), mib(m.peak), oversizeHeapLimit>>20)
	}
	if kept := hostiletest.HeapKept(m.base); kept > 8<<20 {
		t.Fatalf("after the run, %d MiB more heap is in use than before it", kept>>20)
	}
	t.Logf("allocated %.1f MiB, heap peaked %.1f MiB higher; outcome after %v", mib(m.allocated), mib(m.peak), o.took.Round(time.Millisecond))
}

// measured is the heap a run took: how far the heap in use rose above base,
// sampled, and how much the process allocated during the run.
type measured struct{ peak, base, allocated uint64 }

func measure(run func()) measured {
	var allocated uint64
	peak, base := hostiletest.HeapPeak(func() {
		before := hostiletest.Allocated()
		run()
		allocated = hostiletest.Allocated() - before
	})
	return measured{peak: peak, base: base, allocated: allocated}
}

func mib(n uint64) float64 { return float64(n) / (1 << 20) }

func waitFor(d time.Duration, ok func() bool) bool {
	for end := time.Now().Add(d); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			return false
		}
	}
	return true
}

// TestLegacySubmit_PropagationSurvivesHostileSteaks: POST /overlay/submit
// commits a transaction, answers, and leaves the engine propagating it, on a
// goroutine with no recover, to the SHIP hosts its SLAP tracker names. A host
// answering that propagation with null where go-sdk's Broadcaster
// dereferences used to end the process. Through the guarded
// http.DefaultClient, each hostile reply fails the propagation to that host,
// within the bounds the guard sets, and an honest one still succeeds.
func TestLegacySubmit_PropagationSurvivesHostileSteaks(t *testing.T) {
	logs := hostiletest.WatchLogs(t)
	for i, c := range hostiletest.SteakCases(topics.UHRPTopicName) {
		t.Run(c.Name, func(t *testing.T) {
			r := newSteakRun(t, c, i)
			var o outcome
			m := measure(func() { o = r.legacySubmit(c, logs) })
			r.check(t, c, o, m)
		})
	}
}

// TestAdvertisementSync_PropagationSurvivesHostileSteaks: the same replies
// on the advertisement sync path, where SyncAdvertisements, which the node
// runs on a timer, submits the advertisements it creates and the engine
// propagates them before it returns.
func TestAdvertisementSync_PropagationSurvivesHostileSteaks(t *testing.T) {
	logs := hostiletest.WatchLogs(t)
	for i, c := range hostiletest.SteakCases(topics.UHRPTopicName) {
		t.Run(c.Name, func(t *testing.T) {
			r := newSteakRun(t, c, 100+i)
			var o outcome
			m := measure(func() { o = r.syncAdvertisements(logs) })
			r.check(t, c, o, m)
		})
	}
}
