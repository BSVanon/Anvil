package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
)

func TestATipUpdateIsBroadcastWithoutATokenOrPayment(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	origin := op(f.origin, 0)
	v1 := f.move(f.w, f.origin, 0, f.inscribed("v1"))
	rec := post(f.srv, ordtracktest.AtomicBEEF(t, v1), nil)
	if rec.Code != http.StatusOK || broadcastStatus(t, rec) != BroadcastStatusValidatedOnly {
		t.Fatalf("tip update: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("headers %v", rec.Header())
	}
	if !f.srv.broadcaster.Mempool().Has(v1.TxID().String()) {
		t.Fatal("the tip update was not broadcast")
	}
	if got, _, pending, _ := f.tr.ResolveVersion(origin, -1); got != op(v1, 0) || !pending {
		t.Fatalf("latest %s (pending %v), want %s pending", got, pending, op(v1, 0))
	}

	// The JSON form of the body works the same.
	v2 := f.move(f.w, v1, 0, f.inscribed("v2"))
	body, _ := json.Marshal(map[string]string{"beef": hex.EncodeToString(ordtracktest.AtomicBEEF(t, v2))})
	if rec := post(f.srv, body, map[string]string{"Content-Type": "application/json"}); rec.Code != http.StatusOK {
		t.Fatalf("JSON tip update: %d %s", rec.Code, rec.Body.String())
	}
	if f.tip() != op(v2, 0) {
		t.Fatalf("latest %s, want %s", f.tip(), op(v2, 0))
	}

	stats := getStats(t, f.srv)
	if stats["broadcast_tip_credential_used"] != 2 || stats["ordtrack_origins"] != 1 || stats["ordtrack_pending"] != 2 {
		t.Fatalf("tracking stats %v", stats)
	}
}

// getStats is what GET /stats shows under "tracking".
func getStats(t *testing.T, srv *Server) map[string]int64 {
	t.Helper()
	return srv.trackingStats()
}

func TestStatsShowTrackingOnlyWhereItRuns(t *testing.T) {
	f := newTipFixture(t, "test-token", 0)
	get := func(srv *Server) map[string]json.RawMessage {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
		var out map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode /stats %q: %v", rec.Body.String(), err)
		}
		return out
	}
	var tracking map[string]int64
	if err := json.Unmarshal(get(f.srv)["tracking"], &tracking); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"ordtrack_origins", "ordtrack_pending", "ordtrack_rollbacks", "spendwatch_polls", "spendwatch_poll_errors",
		"ordtip_gossip_applied", "ordtip_gossip_rejected", "broadcast_tip_credential_used",
	} {
		if _, ok := tracking[name]; !ok {
			t.Fatalf("no %s in %v", name, tracking)
		}
	}
	if tracking["ordtrack_origins"] != 1 {
		t.Fatalf("tracking %v", tracking)
	}
	if _, ok := get(f.plain)["tracking"]; ok {
		t.Fatal("a node without tracking shows tracking stats")
	}
}

func TestTipUpdateAttemptsAreLimitedPerClient(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	a := map[string]string{"X-Forwarded-For": "203.0.113.7"}
	for i := 0; i < tipCredentialBurst; i++ {
		if rec := post(f.srv, []byte("not a BEEF"), a); rec.Code != http.StatusPaymentRequired {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	v1 := f.move(f.w, f.origin, 0, f.inscribed("v1"))
	beef := ordtracktest.AtomicBEEF(t, v1)
	if rec := post(f.srv, beef, a); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("over the limit: %d %s", rec.Code, rec.Body.String())
	}
	if f.cred.verifies.Load() != 0 || f.tip() != op(f.origin, 0) {
		t.Fatalf("an attempt over the limit reached the tracker: %d verifies, tip %s", f.cred.verifies.Load(), f.tip())
	}
	b := map[string]string{"X-Forwarded-For": "198.51.100.9"}
	if rec := post(f.srv, beef, b); rec.Code != http.StatusOK {
		t.Fatalf("another client: %d %s", rec.Code, rec.Body.String())
	}
	if f.tip() != op(v1, 0) {
		t.Fatalf("tip %s, want %s", f.tip(), op(v1, 0))
	}
}

// A request that brings its own token or payment is judged by the gate
// alone, even when it is a tip update.
func TestRequestsWithCredentialsAreLeftToTheGate(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	v1 := f.move(f.w, f.origin, 0, f.inscribed("v1"))
	beef := ordtracktest.AtomicBEEF(t, v1)
	for _, hdr := range []map[string]string{
		{"X-Anvil-Auth": "wrong"},
		{"Authorization": "Bearer wrong"},
		{"X-App-Token": "x"},
		{HeaderX402Proof: "e30"},
		{HeaderBSVPayment: "00"},
	} {
		got, want := post(f.srv, beef, hdr), post(f.plain, beef, hdr)
		sameReply(t, "credential header", got, want)
		if f.cred.verifies.Load() != 0 || f.tip() != op(f.origin, 0) {
			t.Fatalf("%v: reached the tracker", hdr)
		}
	}
	// A valid token broadcasts it as today; the spend watch then sees it.
	if rec := post(f.srv, beef, map[string]string{"X-Anvil-Auth": "test-token"}); rec.Code != http.StatusOK {
		t.Fatalf("with the token: %d %s", rec.Code, rec.Body.String())
	}
	if f.cred.verifies.Load() != 0 || getStats(t, f.srv)["broadcast_tip_credential_used"] != 0 {
		t.Fatal("a token-authorized broadcast went through the tip credential")
	}
	for deadline := time.Now().Add(5 * time.Second); f.tip() != op(v1, 0); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the observed broadcast was not followed: tip %s", f.tip())
		}
	}
}

// A tip update is recorded only for a 200 reply about the transaction
// verified whose status is not rejected.
func TestRecorderTakesOnlyAnAcceptedBroadcastOfTheVerifiedTx(t *testing.T) {
	txid, other := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	reply := func(id, status string) string {
		b, _ := json.Marshal(BroadcastResponse{TxID: id, Status: status})
		return string(b)
	}
	for _, c := range []struct {
		code int
		body string
		want bool
	}{
		{http.StatusOK, reply(txid, BroadcastStatusPropagated), true},
		{http.StatusOK, reply(txid, BroadcastStatusQueued), true},
		{http.StatusOK, reply(txid, BroadcastStatusValidatedOnly), true},
		{http.StatusOK, reply(txid, BroadcastStatusRejected), false},
		{http.StatusOK, reply(other, BroadcastStatusPropagated), false},
		{http.StatusAccepted, reply(txid, BroadcastStatusPropagated), false},
		{http.StatusOK, "not json", false},
	} {
		rec := &broadcastRecorder{ResponseWriter: httptest.NewRecorder()}
		rec.WriteHeader(c.code)
		_, _ = rec.Write([]byte(c.body))
		if got := rec.succeeded(txid); got != c.want {
			t.Fatalf("%d %s: succeeded %v, want %v", c.code, c.body, got, c.want)
		}
	}
}
