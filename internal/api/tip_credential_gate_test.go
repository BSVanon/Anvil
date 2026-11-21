package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// sameReply fails unless a and b are the same reply, apart from what a
// payment challenge varies per request: its nonce and its expiry.
func sameReply(t *testing.T, name string, a, b *httptest.ResponseRecorder) {
	t.Helper()
	ha, hb := a.Header().Clone(), b.Header().Clone()
	ca, cb := ha.Get(HeaderX402Challenge), hb.Get(HeaderX402Challenge)
	ha.Del(HeaderX402Challenge)
	hb.Del(HeaderX402Challenge)
	if a.Code != b.Code || !reflect.DeepEqual(ha, hb) {
		t.Fatalf("%s: %d %v vs %d %v", name, a.Code, ha, b.Code, hb)
	}
	if ca == "" || cb == "" {
		if ca != cb || a.Body.String() != b.Body.String() {
			t.Fatalf("%s: body %q vs %q", name, a.Body.String(), b.Body.String())
		}
		return
	}
	ja, jb := challengeOf(t, a.Body.Bytes()), challengeOf(t, b.Body.Bytes())
	hca, _ := base64.RawURLEncoding.DecodeString(ca)
	hcb, _ := base64.RawURLEncoding.DecodeString(cb)
	if !reflect.DeepEqual(ja, jb) || !reflect.DeepEqual(challengeOf(t, hca), challengeOf(t, hcb)) {
		t.Fatalf("%s: challenge %+v vs %+v", name, ja, jb)
	}
}

func challengeOf(t *testing.T, b []byte) X402Challenge {
	t.Helper()
	var c X402Challenge
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode challenge %q: %v", b, err)
	}
	c.NonceUTXO, c.ExpiresAt = nil, 0
	return c
}

// unrelatedBEEF is a valid BEEF of a transaction that spends no tip.
func (f *tipFixture) unrelatedBEEF() []byte {
	fund := f.fund(5_000)
	tx := f.w.Spend(f.t, []ordtracktest.In{{Tx: fund}}, ordtracktest.Out{Sats: 4_000})
	f.store.Add(tx)
	return ordtracktest.AtomicBEEF(f.t, tx)
}

// A request that is not a tip update gets today's reply, 402, 401 or 403,
// and never reaches SPV.
func TestRequestsThatAreNotTipUpdatesGetTodaysReplies(t *testing.T) {
	for _, node := range []struct {
		name, token string
		price       int
		want        int
	}{
		{"charging", "test-token", 100, http.StatusPaymentRequired},
		{"token only", "test-token", 0, http.StatusUnauthorized},
		{"no token", "", 0, http.StatusForbidden},
	} {
		f := newTipFixture(t, node.token, node.price)
		roots := f.counted.roots.Load()
		for name, body := range map[string][]byte{
			"unrelated BEEF": f.unrelatedBEEF(),
			"not a BEEF":     []byte("not a BEEF"),
			"empty":          nil,
		} {
			got, want := post(f.srv, body, nil), post(f.plain, body, nil)
			sameReply(t, node.name+", "+name, got, want)
			if got.Code != node.want {
				t.Fatalf("%s, %s: %d, want %d", node.name, name, got.Code, node.want)
			}
			if got.Code == http.StatusPaymentRequired {
				if c := challengeOf(t, got.Body.Bytes()); c.ReqBodySHA256 != sha256Hex(body) {
					t.Fatalf("%s: the gate hashed another body", name)
				}
			}
		}
		if f.cred.verifies.Load() != 0 || f.counted.roots.Load() != roots {
			t.Fatalf("%s: %d verifies, %d root lookups", node.name, f.cred.verifies.Load(), f.counted.roots.Load()-roots)
		}
	}
}

// A transaction that spends the tip without a valid forward spend to a new
// 1-sat output is refused before it is broadcast: it falls through to the
// gate, which wants a payment.
func TestCraftedTipSpendsFallThroughToTheGate(t *testing.T) {
	f := newTipFixture(t, "test-token", 100)
	thief := ordtracktest.NewWallet(t)
	small := f.fund(1_000)
	inflated := f.w.Spend(t, []ordtracktest.In{{Tx: small}}, ordtracktest.Out{Sats: 50_000})
	forged := f.w.Spend(t, []ordtracktest.In{{Tx: inflated}, {Tx: f.origin}}, ordtracktest.Out{Sats: 50_000}, f.inscribed("forged"))
	unmined := f.w.Spend(t, []ordtracktest.In{{Tx: small}}, ordtracktest.Out{Sats: 900})
	deep := f.w.Spend(t, []ordtracktest.In{{Tx: unmined}}, ordtracktest.Out{Sats: 800})
	deeper := f.w.Spend(t, []ordtracktest.In{{Tx: deep}, {Tx: f.origin}}, ordtracktest.Out{Sats: 800}, f.inscribed("deep"))
	claimed := f.move(thief, f.origin, 0, f.inscribed("claimed"))
	ordtracktest.NewChain().Mine(claimed) // a merkle path to a block the node does not hold
	for name, tx := range map[string]*transaction.Transaction{
		"wrong key on the token input": f.move(thief, f.origin, 0, f.inscribed("stolen")),
		"sat lands in a larger output": f.move(f.w, f.origin, 0, ordtracktest.Out{Sats: 5_000}),
		"forged input value":           forged,
		"unmined ancestry too deep":    deeper,
		"mined, without a proof":       claimed,
	} {
		before := f.cred.verifies.Load()
		beef := ordtracktest.AtomicBEEF(t, tx)
		got, want := post(f.srv, beef, nil), post(f.plain, beef, nil)
		sameReply(t, name, got, want)
		if got.Code != http.StatusPaymentRequired || f.cred.verifies.Load() != before+1 {
			t.Fatalf("%s: %d, verified %d times", name, got.Code, f.cred.verifies.Load()-before)
		}
		if f.srv.broadcaster.Mempool().Has(tx.TxID().String()) || f.tip() != op(f.origin, 0) {
			t.Fatalf("%s: broadcast or recorded", name)
		}
	}
	if getStats(t, f.srv)["broadcast_tip_credential_used"] != 0 {
		t.Fatal("a crafted spend counted as a tip credential")
	}
}

// With no tracked origin, /broadcast and /content answer exactly as on a
// node without tracking.
func TestNoTrackedOriginLeavesBroadcastAndContentUnchanged(t *testing.T) {
	for _, node := range []struct {
		token string
		price int
	}{{"test-token", 100}, {"test-token", 0}, {"", 0}} {
		f := newTipFixture(t, node.token, node.price)
		f.tr.SetTracked(nil)
		for deadline := time.Now().Add(5 * time.Second); f.tr.Active(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("still active")
			}
		}
		f.srv.ContentServer().SetVersions(f.tr, time.Minute)
		v1 := f.move(f.w, f.origin, 0, f.inscribed("v1"))
		tipBEEF := ordtracktest.AtomicBEEF(t, v1)
		unrelated := f.unrelatedBEEF()
		for name, req := range map[string]struct {
			body []byte
			hdr  map[string]string
		}{
			"a former tip update": {tipBEEF, nil},
			"unrelated":           {unrelated, nil},
			"not a BEEF":          {[]byte("x"), nil},
			"with the token":      {unrelated, map[string]string{"X-Anvil-Auth": "test-token"}},
			"invalid with token":  {[]byte("x"), map[string]string{"X-Anvil-Auth": "test-token"}},
		} {
			sameReply(t, name, post(f.srv, req.body, req.hdr), post(f.plain, req.body, req.hdr))
		}
		for _, path := range []string{"/content/" + op(f.origin, 0), "/content/" + op(v1, 0), "/content/" + f.origin.TxID().String()} {
			a, b := httptest.NewRecorder(), httptest.NewRecorder()
			f.srv.Handler().ServeHTTP(a, httptest.NewRequest(http.MethodGet, path, nil))
			f.plain.Handler().ServeHTTP(b, httptest.NewRequest(http.MethodGet, path, nil))
			sameReply(t, path, a, b)
		}
		if f.cred.verifies.Load() != 0 {
			t.Fatalf("%d verifies with nothing tracked", f.cred.verifies.Load())
		}
	}
}
