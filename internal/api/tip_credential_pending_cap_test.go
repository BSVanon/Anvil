package api

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
)

const trackedPendingLinkCap = 25

func TestTipCredentialRefusesBroadcastAtThePendingCap(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	prev := f.origin
	for i := 0; i < trackedPendingLinkCap; i++ {
		next := f.move(f.w, prev, 0, f.inscribed(fmt.Sprintf("v%d", i+1)))
		hdr := map[string]string{"X-Forwarded-For": fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)}
		if rec := post(f.srv, ordtracktest.AtomicBEEF(t, next), hdr); rec.Code != http.StatusOK {
			t.Fatalf("link %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
		prev = next
	}
	stuckTip := op(prev, 0)
	stats := getStats(t, f.srv)
	if f.tip() != stuckTip || stats["ordtrack_pending"] != trackedPendingLinkCap {
		t.Fatalf("tip %s, pending %d", f.tip(), stats["ordtrack_pending"])
	}
	usedAtCap := stats["broadcast_tip_credential_used"]

	over := f.move(f.w, prev, 0, f.inscribed("over-cap"))
	beef := ordtracktest.AtomicBEEF(t, over)
	hdr := map[string]string{"X-Forwarded-For": "203.0.114.1"}
	got := post(f.srv, beef, hdr)
	sameReply(t, "pending cap", got, post(f.plain, beef, hdr))
	if f.srv.broadcaster.Mempool().Has(over.TxID().String()) {
		t.Fatal("over-cap transaction was broadcast")
	}
	after := getStats(t, f.srv)
	if f.tip() != stuckTip || after["ordtrack_pending"] != trackedPendingLinkCap {
		t.Fatalf("state changed past cap: tip %s, pending %d", f.tip(), after["ordtrack_pending"])
	}
	if after["broadcast_tip_credential_used"] != usedAtCap {
		t.Fatalf("credential counter changed for an unrecorded link: %d -> %d", usedAtCap, after["broadcast_tip_credential_used"])
	}
}
