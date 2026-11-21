package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
)

type nonRecordingTipCredential struct{ TipCredential }

func (c nonRecordingTipCredential) VerifyTipUpdate(ctx context.Context, n *beefnorm.BEEF, origin, tip string) (func(bool) bool, error) {
	complete, err := c.TipCredential.VerifyTipUpdate(ctx, n, origin, tip)
	if err != nil {
		return nil, err
	}
	return func(bool) bool {
		complete(false)
		return false
	}, nil
}

func TestTipCredentialCounterCountsOnlyRecordedLinks(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	f.srv.SetTipCredential(nonRecordingTipCredential{TipCredential: f.cred}, f.tr.Stats)
	v1 := f.move(f.w, f.origin, 0, f.inscribed("v1"))
	rec := post(f.srv, ordtracktest.AtomicBEEF(t, v1), nil)
	if rec.Code != http.StatusOK || !f.srv.broadcaster.Mempool().Has(v1.TxID().String()) {
		t.Fatalf("broadcast: %d %s", rec.Code, rec.Body.String())
	}
	if used := getStats(t, f.srv)["broadcast_tip_credential_used"]; used != 0 {
		t.Fatalf("counter = %d, want 0 for an unrecorded link", used)
	}
}
