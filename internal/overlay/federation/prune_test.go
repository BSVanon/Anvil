package federation

import (
	"context"
	"testing"

	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/types"
)

// TestPruneDuplicatesByDomain verifies the prune keeps exactly one (newest)
// record per topic/service for our domain, deletes the rest, leaves other
// domains untouched, and honors dry-run.
func TestPruneDuplicatesByDomain(t *testing.T) {
	stepClock(t) // deterministic increasing CreatedAt
	ctx := context.Background()
	db := newTestDB(t)
	ship := NewSHIPStorage(db)
	slap := NewSLAPStorage(db)

	const ours = "https://anvil-a.test"
	const peer = "https://peer.test"

	// Our domain: 3 dup tm_uhrp + 2 dup tm_kvstore. Peer: 1 tm_uhrp (must survive).
	for i, vout := range []int{0, 1, 2} {
		if err := ship.StoreSHIPRecord(ctx, "txU", vout, "id", ours, "tm_uhrp"); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	if err := ship.StoreSHIPRecord(ctx, "txK", 0, "id", ours, "tm_kvstore"); err != nil {
		t.Fatal(err)
	}
	if err := ship.StoreSHIPRecord(ctx, "txK", 1, "id", ours, "tm_kvstore"); err != nil {
		t.Fatal(err)
	}
	if err := ship.StoreSHIPRecord(ctx, "txP", 0, "id", peer, "tm_uhrp"); err != nil {
		t.Fatal(err)
	}
	// SLAP: 2 dup ls_uhrp for ours.
	if err := slap.StoreSLAPRecord(ctx, "txS", 0, "id", ours, "ls_uhrp"); err != nil {
		t.Fatal(err)
	}
	if err := slap.StoreSLAPRecord(ctx, "txS", 1, "id", ours, "ls_uhrp"); err != nil {
		t.Fatal(err)
	}

	// Dry run: reports deletions but changes nothing.
	plan, err := ship.PruneDuplicatesByDomain(ctx, ours, false)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if plan.Kept != 2 || plan.Deleted != 3 { // keep 1 uhrp + 1 kvstore; delete 2 uhrp + 1 kvstore
		t.Fatalf("dry-run SHIP plan: kept %d deleted %d (want 2/3)", plan.Kept, plan.Deleted)
	}
	if all, _ := ship.FindAll(ctx, nil, nil, nil); len(all) != 6 {
		t.Fatalf("dry run must not delete: have %d records (want 6)", len(all))
	}

	// Apply.
	if _, err := ship.PruneDuplicatesByDomain(ctx, ours, true); err != nil {
		t.Fatalf("apply SHIP: %v", err)
	}
	if _, err := slap.PruneDuplicatesByDomain(ctx, ours, true); err != nil {
		t.Fatalf("apply SLAP: %v", err)
	}

	// Our domain: exactly 1 tm_uhrp + 1 tm_kvstore left.
	ourDom := ours
	got, _ := ship.FindRecord(ctx, types.SHIPQuery{Domain: &ourDom})
	if len(got) != 2 {
		t.Fatalf("after prune, our SHIP records = %d (want 2)", len(got))
	}
	// Peer untouched.
	peerDom := peer
	gp, _ := ship.FindRecord(ctx, types.SHIPQuery{Domain: &peerDom})
	if len(gp) != 1 {
		t.Fatalf("peer SHIP records = %d (want 1, must be untouched)", len(gp))
	}
	// SLAP: 1 ls_uhrp left.
	gs, _ := slap.FindRecord(ctx, types.SLAPQuery{Domain: &ourDom})
	if len(gs) != 1 {
		t.Fatalf("after prune, our SLAP records = %d (want 1)", len(gs))
	}
}
