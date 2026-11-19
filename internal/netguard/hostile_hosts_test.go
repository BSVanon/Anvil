package netguard

import (
	"context"
	"strconv"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestGuard_ManyHostileHostsStayWithinTheLookupBudget: one stock go-sdk
// LookupResolver query reaches hostiletest.CostliestHosts hosts at once, each
// answering with the costliest reply the guard lets through, and one more host
// past each per-answer cap. The process must survive, every costliest reply
// must reach the merged answer, no reply past a cap may, and the heap in use
// must stay within the lookup budget plus a margin. Without the shared
// decoding slots, or without any one cap, it does not.
func TestGuard_ManyHostileHostsStayWithinTheLookupBudget(t *testing.T) {
	canary := hostiletest.NewCanary(t)
	good := hostiletest.Costliest(t, canary, hostiletest.CostliestHosts)
	past := hostiletest.PastTheCaps(t, canary)
	var hosts []string
	for _, r := range append(append([]*hostiletest.Reply{}, good...), past...) {
		url, _ := hostiletest.Serve(t, r)
		hosts = append(hosts, url)
	}

	var answer *lookup.LookupAnswer
	var err error
	peak, base := hostiletest.HeapPeak(func() {
		resolver := lookup.NewLookupResolver(&lookup.LookupResolver{SLAPTrackers: hosts})
		answer, err = resolver.Query(context.Background(), slapQuestion)
	})
	t.Logf("peak heap in use %.1f MiB above a %.1f MiB base", float64(peak)/(1<<20), float64(base)/(1<<20))
	if err != nil {
		t.Fatalf("the query must succeed on the costliest replies: %v", err)
	}
	merged := mergedKeys(t, answer)
	for _, r := range good {
		if !merged[r.Marker] {
			t.Errorf("the costliest reply %s did not reach the merged answer", r.Name)
		}
	}
	for _, r := range past {
		if merged[r.Marker] {
			t.Errorf("%s, past its cap, reached the merged answer", r.Name)
		}
	}
	if limit := uint64(hostiletest.LookupBudget + hostiletest.HeapMargin); peak > limit {
		t.Errorf("peak heap in use %d MiB above base, over the %d MiB budget plus %d MiB margin",
			peak>>20, hostiletest.LookupBudget>>20, hostiletest.HeapMargin>>20)
	}
}

// mergedKeys returns the "txid.index" key of every output of a resolver's
// merged answer, computed as the resolver computes it.
func mergedKeys(t *testing.T, answer *lookup.LookupAnswer) map[string]bool {
	t.Helper()
	keys := make(map[string]bool, len(answer.Outputs))
	for _, out := range answer.Outputs {
		_, tx, _, err := transaction.ParseBeef(out.Beef)
		if err != nil || tx == nil {
			t.Fatalf("a merged output does not parse: %v", err)
		}
		keys[tx.TxID().String()+"."+strconv.FormatUint(uint64(out.OutputIndex), 10)] = true
	}
	return keys
}
