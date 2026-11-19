package v3engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
)

// TestEngine_PropagationStaysWithinTheLookupBudget: an admitted submit's
// propagation asks every SLAP tracker of the engine for ls_ship hosts at once
// (go-sdk's FindCompetentHosts, on http.DefaultClient). Here
// hostiletest.CostliestHosts trackers answer with the costliest reply the
// guard lets through, and one more tracker past each per-answer cap; each
// reply advertises a canary host of its own. The submit must return with its
// output admitted, propagation must query the host every costliest reply
// advertises and none that a reply past a cap advertises, and the heap in use
// must stay within the lookup budget plus a margin. Without the shared
// decoding slots it does not.
func TestEngine_PropagationStaysWithinTheLookupBudget(t *testing.T) {
	canary := hostiletest.NewCanary(t)
	good := hostiletest.Costliest(t, canary, hostiletest.CostliestHosts)
	past := hostiletest.PastTheCaps(t, canary)
	var trackers []string
	for _, r := range append(append([]*hostiletest.Reply{}, good...), past...) {
		url, _ := hostiletest.Serve(t, r)
		trackers = append(trackers, url)
	}

	eng, _ := newTestEngine(t)
	eng.Advertiser = stubAdvertiser{}
	eng.SLAPTrackers = trackers
	tagged := buildUHRPTaggedBEEF(t, strings.Repeat("f", 64), "https://example.test/p", "image/png", true)

	var err error
	peak, base := hostiletest.HeapPeak(func() {
		done := make(chan error, 1)
		go func() {
			steak, err := eng.Submit(context.Background(), tagged, engine.SubmitModeCurrent, nil)
			if ai := steak[topics.UHRPTopicName]; err == nil && (ai == nil || len(ai.OutputsToAdmit) != 1) {
				err = errors.New("the UHRP output was not admitted, so nothing was propagated")
			}
			done <- err
		}()
		select {
		case err = <-done:
		case <-time.After(2 * time.Minute):
			err = errors.New("the submit did not return")
		}
	})
	t.Logf("peak heap in use %.1f MiB above a %.1f MiB base", float64(peak)/(1<<20), float64(base)/(1<<20))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	for _, r := range good {
		if canary.Hits(r.Name) == 0 {
			t.Errorf("propagation never queried the host %s advertises", r.Name)
		}
	}
	for _, r := range past {
		if canary.Hits(r.Name) != 0 {
			t.Errorf("propagation queried the host %s advertises, past its cap", r.Name)
		}
	}
	if limit := uint64(hostiletest.LookupBudget + hostiletest.HeapMargin); peak > limit {
		t.Errorf("peak heap in use %d MiB above base, over the %d MiB budget plus %d MiB margin",
			peak>>20, hostiletest.LookupBudget>>20, hostiletest.HeapMargin>>20)
	}
}
