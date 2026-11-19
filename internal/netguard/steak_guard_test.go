package netguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

const testTopic = "tm_test"

// generator is the compressed secp256k1 generator point, the identity key
// field go-sdk's admin-token decoder needs in front of an advertisement.
var generator = []byte{0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
	0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98}

// shipAd returns the BEEF of a transaction with no inputs whose one output
// advertises host for topic over SHIP, distinct by id.
func shipAd(host, topicName string, id uint32) []byte {
	s := &script.Script{}
	_ = s.AppendPushData(generator)
	_ = s.AppendOpcodes(script.OpCHECKSIG)
	for _, field := range []string{"SHIP", string(generator), host, topicName} {
		_ = s.AppendPushData([]byte(field))
	}
	_ = s.AppendOpcodes(script.Op2DROP, script.Op2DROP)
	tx := transaction.NewTransaction()
	tx.LockTime = id
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: s, Satoshis: 1})
	beef, err := tx.BEEF()
	if err != nil {
		panic(err) // a transaction with no inputs always serializes
	}
	return beef
}

// shipHostFor serves an ls_ship answer advertising every one of hosts for
// testTopic, as a SHIP host's lookup does.
func shipHostFor(t *testing.T, hosts []string) string {
	t.Helper()
	answer := &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList}
	for i, h := range hosts {
		answer.Outputs = append(answer.Outputs, &lookup.OutputListItem{Beef: shipAd(h, testTopic, uint32(i)), OutputIndex: 0})
	}
	body, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := serveAnswer(t, "application/json", body, false)
	return url
}

// stockBroadcaster is go-overlay-services' propagation Broadcaster for
// testTopic, asking shipHost for interested hosts, with facilitator f, or
// go-sdk's default facilitator on http.DefaultClient when f is nil.
func stockBroadcaster(t *testing.T, shipHost string, f topic.Facilitator) *topic.Broadcaster {
	t.Helper()
	resolver := lookup.NewLookupResolver(&lookup.LookupResolver{HostOverrides: map[string][]string{"ls_ship": {shipHost}}})
	b, err := topic.NewBroadcaster([]string{testTopic}, &topic.BroadcasterConfig{Resolver: resolver, Facilitator: f})
	if err != nil {
		t.Fatalf("NewBroadcaster: %v", err)
	}
	return b
}

// broadcastTx is a transaction above overlaytest's mined funding output, so
// go-sdk can build its Atomic BEEF; it has one output and one input.
func broadcastTx(t *testing.T) *transaction.Transaction {
	t.Helper()
	lock := script.Script{script.OpTRUE}
	return overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
}

// steakHost answers every /submit with reply, streamed with no
// Content-Length when chunked is set, and counts the submits.
func steakHost(t *testing.T, reply *hostiletest.Reply, chunked bool) (string, *atomic.Int64) {
	t.Helper()
	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if !chunked {
			w.Header().Set("Content-Length", strconv.FormatInt(reply.Len(), 10))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = reply.WriteTo(w)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// oversizeSteak is a 64 MiB STEAK of repeated empty topics.
func oversizeSteak() *hostiletest.Reply {
	return hostiletest.Repeated("oversize", []byte(`{`), []byte(`"k":{},`), (64<<20)/7, []byte(`"k":{}}`))
}

// TestGuard_StockBroadcasterSurvivesHostileSteaks: a host answers the
// propagation POST /submit with a reply go-sdk's Broadcaster cannot survive
// (null where it dereferences, so a panic at topic/broadcaster.go:177 or
// :178), cannot decode, or should not trust. Through http.DefaultClient, the
// stock facilitator gets the guard's error and the stock Broadcaster, on the
// path go-overlay-services propagation takes, fails for that host and
// returns. On an unguarded client the null replies panic it.
func TestGuard_StockBroadcasterSurvivesHostileSteaks(t *testing.T) {
	ctx := context.Background()
	tx := broadcastTx(t)
	beef, err := tx.AtomicBEEF(false)
	if err != nil {
		t.Fatalf("AtomicBEEF: %v", err)
	}
	tagged := &overlay.TaggedBEEF{Beef: beef, Topics: []string{testTopic}}
	for _, h := range []struct {
		name    string
		reply   *hostiletest.Reply
		chunked bool
		want    string
		panics  bool // on an unguarded client
	}{
		{"null", hostiletest.Literal("null", []byte(`null`)), false, "the reply is null, not an object", true},
		{"topic null", hostiletest.Literal("topic null", []byte(`{"tm_test":null}`)), false, `topic "tm_test" is null`, true},
		{"wrong type", hostiletest.Literal("wrong type", []byte(`{"tm_test":{"outputsToAdmit":"all"}}`)), false, "is a string, not a list", false},
		{"negative index", hostiletest.Literal("negative", []byte(`{"tm_test":{"outputsToAdmit":[-1]}}`)), true, "not a uint32 index", false},
		{"index past the outputs", hostiletest.Literal("past", []byte(`{"tm_test":{"outputsToAdmit":[4000000000]}}`)), false, "fewer than", false},
		{"oversize streamed", oversizeSteak(), true, "/submit reply body is over 1048576 bytes", false},
		{"oversize declared", oversizeSteak(), false, "/submit reply Content-Length 67108868 is over 1048576 bytes", false},
	} {
		t.Run(h.name, func(t *testing.T) {
			url, hits := steakHost(t, h.reply, h.chunked)

			_, err := noPanicValue(t, "facilitator", func() (*overlay.Steak, error) {
				return (&topic.HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}).Send(url, tagged)
			})
			if err == nil || !strings.Contains(err.Error(), "netguard: ") || !strings.Contains(err.Error(), h.want) {
				t.Fatalf("expected the guard to refuse the reply with %q, got: %v", h.want, err)
			}

			ship := shipHostFor(t, []string{url})
			_, failure := noPanicValue(t, "Broadcaster", func() (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
				return stockBroadcaster(t, ship, nil).BroadcastCtx(ctx, tx)
			})
			if failure == nil || failure.Code != "ERR_ALL_HOSTS_REJECTED" {
				t.Fatalf("expected the host's reply to count as a failure, got %+v", failure)
			}
			if got := hits.Load(); got != 2 {
				t.Fatalf("expected the facilitator and the Broadcaster to reach the host, got %d submits", got)
			}

			if h.panics {
				unguarded := &topic.HTTPSOverlayBroadcastFacilitator{Client: &http.Client{}}
				if !panics(func() { stockBroadcaster(t, ship, unguarded).BroadcastCtx(ctx, tx) }) {
					t.Fatal("on an unguarded client this reply must panic go-sdk's Broadcaster, or the case tests nothing")
				}
			}
		})
	}
}

// TestGuard_PassesHonestSteaks: the STEAK shapes honest peers send reach
// go-sdk's facilitator through http.DefaultClient as go-sdk reads them on an
// unguarded client, and the stock Broadcaster counts them as acknowledgements.
func TestGuard_PassesHonestSteaks(t *testing.T) {
	ctx := context.Background()
	tx := broadcastTx(t)
	beef, err := tx.AtomicBEEF(false)
	if err != nil {
		t.Fatalf("AtomicBEEF: %v", err)
	}
	tagged := &overlay.TaggedBEEF{Beef: beef, Topics: []string{testTopic}}
	for _, tc := range []struct{ name, body string }{
		{"go-sdk encoding", `{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":[0],"ancillaryTxids":["` + someTxid + `"]}}`},
		{"TypeScript overlay", `{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":[0]}}`},
		{"Anvil canonical", `{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":[],"ancillaryTxIDs":[]}}`},
		{"Anvil legacy", `{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":null}}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, chunked := range []bool{false, true} {
				url, _ := steakHost(t, hostiletest.Literal(tc.name, []byte(tc.body)), chunked)
				want, err := (&topic.HTTPSOverlayBroadcastFacilitator{Client: &http.Client{}}).Send(url, tagged)
				if err != nil {
					t.Fatalf("unguarded facilitator: %v", err)
				}
				got, err := (&topic.HTTPSOverlayBroadcastFacilitator{Client: http.DefaultClient}).Send(url, tagged)
				if err != nil || !sameSteak(*got, *want) {
					t.Fatalf("guarded facilitator differs (chunked %v): err %v\n got  %s\n want %s", chunked, err, dumpPtr(got), dump(*want))
				}
				success, failure := stockBroadcaster(t, shipHostFor(t, []string{url}), nil).BroadcastCtx(ctx, tx)
				if failure != nil || success == nil {
					t.Fatalf("the Broadcaster must accept the acknowledgement, got %+v", failure)
				}
			}
		})
	}
}

// TestGuard_ARefusedSteakFailsOnlyItsHost: a refused reply is a transport
// error for the host that sent it. A send that reaches a hostile host and an
// honest one still succeeds on the honest host's acknowledgement.
func TestGuard_ARefusedSteakFailsOnlyItsHost(t *testing.T) {
	hostile, _ := steakHost(t, hostiletest.Literal("null", []byte(`null`)), false)
	honest, _ := steakHost(t, hostiletest.Literal("honest", []byte(`{"tm_test":{"outputsToAdmit":[0],"coinsToRetain":[]}}`)), false)
	success, failure := noPanicValue(t, "Broadcaster", func() (*transaction.BroadcastSuccess, *transaction.BroadcastFailure) {
		return stockBroadcaster(t, shipHostFor(t, []string{hostile, honest}), nil).BroadcastCtx(context.Background(), broadcastTx(t))
	})
	if failure != nil || success == nil || !strings.Contains(success.Message, "Sent to 1 Overlay Service host") {
		t.Fatalf("want the honest host's acknowledgement alone, got %+v, %+v", success, failure)
	}
}

func dumpPtr(s *overlay.Steak) string {
	if s == nil {
		return "nil"
	}
	return dump(*s)
}

// TestGuard_OversizeSteaksStayWithinTheirMemory: one stock Broadcaster send
// reaches 8 hosts that each stream a 64 MiB STEAK. Each reply is cut off just
// past MaxSteakBytes, so the heap in use stays within 8 x 3 x MaxSteakBytes,
// 24 MiB, plus a margin for the test's servers and connections, where reading
// the replies whole would take 8 x 64 MiB; and once the send returns, nothing
// it read is kept.
func TestGuard_OversizeSteaksStayWithinTheirMemory(t *testing.T) {
	const hosts = 8
	var urls []string
	var hits []*atomic.Int64
	for range hosts {
		url, n := steakHost(t, oversizeSteak(), true)
		urls, hits = append(urls, url), append(hits, n)
	}
	ship := shipHostFor(t, urls)
	tx := broadcastTx(t)

	var failure *transaction.BroadcastFailure
	peak, base := hostiletest.HeapPeak(func() {
		_, failure = stockBroadcaster(t, ship, nil).BroadcastCtx(context.Background(), tx)
	})
	t.Logf("peak heap in use %.1f MiB above a %.1f MiB base", float64(peak)/(1<<20), float64(base)/(1<<20))
	if failure == nil || failure.Code != "ERR_ALL_HOSTS_REJECTED" {
		t.Fatalf("every oversize reply must be refused, got %+v", failure)
	}
	for i, n := range hits {
		if n.Load() != 1 {
			t.Fatalf("host %d received %d submits, want 1", i, n.Load())
		}
	}
	const margin = 16 << 20
	if limit := uint64(hosts*3*MaxSteakBytes + margin); peak > limit {
		t.Errorf("peak heap in use %d MiB above base, over %d MiB for %d capped replies plus %d MiB margin",
			peak>>20, (hosts*3*MaxSteakBytes)>>20, hosts, margin>>20)
	}
	assertNothingKept(t, base)
}

// TestGuard_SteakReadsAreBoundedByPermits: one stock Broadcaster send reaches
// 64 hosts that each declare a MaxSteakBytes reply and stall part way, until
// the exchange's deadline (1 s here). Each reply read holds one exact
// MaxSteakBytes buffer, but at most steakReadPermits are read at once, so the
// heap in use stays within twice steakReadPermits x MaxSteakBytes, 32 MiB,
// plus a margin, where 64 reads at once hold 64 MiB live; the replies past
// the permits fail at the deadline having read nothing.
func TestGuard_SteakReadsAreBoundedByPermits(t *testing.T) {
	const hosts = 64
	stop := make(chan struct{})
	var urls []string
	for range hosts {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Length", strconv.FormatInt(MaxSteakBytes, 10))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"tm_test":{"outputsToAdmit":[`))
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-stop:
			}
		}))
		t.Cleanup(srv.Close)
		urls = append(urls, srv.URL)
	}
	t.Cleanup(func() { close(stop) }) // runs first, so the servers do not wait on their handlers
	ship := shipHostFor(t, urls)
	tx := broadcastTx(t)
	g := &guard{base: http.DefaultTransport, maxBytes: MaxResponseBytes, maxSteakBytes: MaxSteakBytes, submitTimeout: time.Second}
	f := &topic.HTTPSOverlayBroadcastFacilitator{Client: &http.Client{Transport: g}}
	// One send that fails at once first, so the measured send's base holds
	// what the stack allocates only on first use.
	warm, _ := steakHost(t, hostiletest.Literal("warm-up", []byte(`null`)), false)
	_, _ = stockBroadcaster(t, shipHostFor(t, []string{warm}), f).BroadcastCtx(context.Background(), tx)

	var most atomic.Int64
	sampled := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			if n := int64(steakReads.InUse()); n > most.Load() {
				most.Store(n)
			}
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	var failure *transaction.BroadcastFailure
	peak, base := hostiletest.HeapPeak(func() {
		_, failure = stockBroadcaster(t, ship, f).BroadcastCtx(context.Background(), tx)
	})
	close(done)
	<-sampled
	t.Logf("peak heap in use %.1f MiB above a %.1f MiB base; at most %d STEAK reads at once",
		float64(peak)/(1<<20), float64(base)/(1<<20), most.Load())
	if failure == nil || failure.Code != "ERR_ALL_HOSTS_REJECTED" {
		t.Fatalf("every stalled reply must fail, got %+v", failure)
	}
	if most.Load() != steakReadPermits {
		t.Errorf("at most %d STEAK reads ran at once, want all %d permits used and no more", most.Load(), steakReadPermits)
	}
	// The permits hold steakReadPermits buffers live, and as many again can
	// be the buffers of reads cut off at the deadline that a collection has
	// yet to free, when replies waiting for a permit take one just before
	// their own deadline. The margin covers the 64 servers' and
	// connections' buffers.
	const margin = 16 << 20
	if limit := uint64(2*steakReadPermits*MaxSteakBytes + margin); peak > limit {
		t.Errorf("peak heap in use %d MiB above base, over the %d MiB the permits allow plus %d MiB margin",
			peak>>20, (2*steakReadPermits*MaxSteakBytes)>>20, margin>>20)
	}
	if n := steakReads.InUse(); n != 0 {
		t.Errorf("%d STEAK read permits are still taken", n)
	}
	assertNothingKept(t, base)
}

// assertNothingKept fails the test if, after a garbage collection, the heap
// in use is more than 8 MiB above base.
func assertNothingKept(t *testing.T, base uint64) {
	t.Helper()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if kept := int64(m.HeapInuse) - int64(base); kept > 8<<20 {
		t.Errorf("after the send, %d MiB more heap is in use than before it", kept>>20)
	}
}

// noPanicValue runs f and fails the test if it panics in this goroutine.
func noPanicValue[A, B any](t *testing.T, what string, f func() (A, B)) (a A, b B) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	return f()
}

// panics reports whether f panics in this goroutine.
func panics(f func()) (did bool) {
	defer func() { did = recover() != nil }()
	f()
	return false
}
