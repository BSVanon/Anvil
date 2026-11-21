package api

import (
	"net/http"
	"testing"

	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
)

func TestTipPropertyCredentialHeadersNeverUseFreePath(t *testing.T) {
	rows := []struct {
		name   string
		header string
		value  string
	}{
		{"operator header", "X-Anvil-Auth", "wrong"},
		{"bearer header", "Authorization", "Bearer wrong"},
		{"app token", "X-App-Token", "present"},
		{"proof", HeaderX402Proof, "e30"},
		{"direct", HeaderBSVPayment, "00"},
		{"BRC-121 BEEF", headerBRC121Beef, "present"},
		{"BRC-121 sender", headerBRC121Sender, "present"},
		{"BRC-121 nonce", headerBRC121Nonce, "present"},
		{"BRC-121 time", headerBRC121Time, "present"},
		{"BRC-121 vout", headerBRC121Vout, "present"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := newTipFixture(t, "test-token", 100)
			next := f.move(f.w, f.origin, 0, f.inscribed("next"))
			body := ordtracktest.AtomicBEEF(t, next)
			got := post(f.srv, body, map[string]string{row.header: row.value})
			want := post(f.plain, body, map[string]string{row.header: row.value})
			sameReply(t, row.name, got, want)
			if f.cred.verifies.Load() != 0 || f.tip() != op(f.origin, 0) || getStats(t, f.srv)["broadcast_tip_credential_used"] != 0 {
				t.Fatalf("credential header reached the free path")
			}
		})
	}
}

func TestTipPropertyFailedBroadcastReleasesReservation(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newTipFixture(t, "test-token", 100)
			next := f.move(f.w, f.origin, 0, f.inscribed("next"))
			body := ordtracktest.AtomicBEEF(t, next)
			f.srv.mux = http.NewServeMux()
			f.srv.mux.HandleFunc("POST /broadcast", f.srv.tipCredential(
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) },
				f.srv.authOrPayBinary(f.srv.handleBroadcast),
			))
			if w := post(f.srv, body, nil); w.Code != status {
				t.Fatalf("failed handler = %d, want %d", w.Code, status)
			}
			if f.tip() != op(f.origin, 0) || getStats(t, f.srv)["broadcast_tip_credential_used"] != 0 {
				t.Fatal("failed handler recorded the reserved link")
			}
			rebuildRoutes(f.srv)
			if w := post(f.srv, body, nil); w.Code != http.StatusOK {
				t.Fatalf("retry after release = %d %s", w.Code, w.Body.String())
			}
			if f.tip() != op(next, 0) || getStats(t, f.srv)["broadcast_tip_credential_used"] != 1 {
				t.Fatal("successful retry was not recorded exactly once")
			}
		})
	}
}
