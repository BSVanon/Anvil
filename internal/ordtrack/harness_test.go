package ordtrack

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/BSVanon/Anvil/internal/spendwatch"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeWoC answers WhatsOnChain's spent-output endpoint from a map: an
// outpoint set to a txid is spent by it, one set to "down" answers 503 (an
// answer the spend watch does not cache), any other answers 404, unspent.
type fakeWoC struct {
	srv   *httptest.Server
	mu    sync.Mutex
	state map[string]string
	calls atomic.Int64
}

func newFakeWoC(t *testing.T) *fakeWoC {
	f := &fakeWoC{state: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWoC) serve(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "tx" || parts[3] != "spent" {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	s := f.state[parts[1]+"_"+parts[2]]
	f.mu.Unlock()
	switch s {
	case "":
		http.Error(w, "Not Found", http.StatusNotFound)
	case "down":
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	default:
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_, _ = fmt.Fprintf(w, `{"txid":%q,"vin":0,"status":"unconfirmed"}`, s)
	}
}

func (f *fakeWoC) set(outpoint, state string) {
	f.mu.Lock()
	f.state[outpoint] = state
	f.mu.Unlock()
}

// source is the node's fetch and tx-status paths over a test store.
type source struct {
	store    *ordtracktest.Store
	statuses atomic.Int64
}

func (s *source) Tx(ctx context.Context, txid string) (*transaction.Transaction, error) {
	return s.store.Tx(ctx, txid)
}

func (s *source) Status(_ context.Context, txid string) (Status, error) {
	s.statuses.Add(1)
	known, mined, height := s.store.Mined(txid)
	return Status{Known: known, Mined: mined, Height: height}, nil
}

// rawSource is the content server's P2P fetch over a test store.
type rawSource struct{ store *ordtracktest.Store }

func (r rawSource) FetchRawTx(txid string) (string, error) {
	tx, err := r.store.Tx(context.Background(), txid)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tx.Bytes()), nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// harness is a tracker over an in-memory chain, store and WhatsOnChain,
// driven by hand: tests call what Run would call.
type harness struct {
	t     *testing.T
	ctx   context.Context
	w     *ordtracktest.Wallet
	chain *ordtracktest.Chain
	store *ordtracktest.Store
	src   *source
	woc   *fakeWoC
	clock *clock
	key   *ec.PrivateKey
	dir   string

	watch    *spendwatch.Watcher
	tr       *Tracker
	spvCalls atomic.Int64

	mu        sync.Mutex
	published []*envelope.Envelope
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t: t, ctx: context.Background(),
		w: ordtracktest.NewWallet(t), chain: ordtracktest.NewChain(), store: ordtracktest.NewStore(),
		woc: newFakeWoC(t), clock: &clock{t: time.Unix(1_800_000_000, 0)}, key: key, dir: t.TempDir(),
	}
	h.src = &source{store: h.store}
	h.open()
	return h
}

// open starts a tracker and its spend watch over the harness's version
// store.
func (h *harness) open() {
	h.t.Helper()
	h.watch = spendwatch.New(spendwatch.Config{
		WoCBase: h.woc.srv.URL, RequestGap: time.Microsecond,
		BackoffBase: time.Millisecond, BackoffMax: time.Millisecond, Logger: discard,
	})
	tr, err := New(Config{
		Path: filepath.Join(h.dir, "ordtrack"), Source: h.src, Chain: h.chain, Watcher: h.watch,
		Publish: h.publish, SigningKey: h.key, Logger: discard,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	tr.now = h.clock.now
	inner := tr.v.spvVerify
	tr.v.spvVerify = func(ctx context.Context, tx *transaction.Transaction, ct chaintracker.ChainTracker, fm transaction.FeeModel) (bool, error) {
		h.spvCalls.Add(1)
		return inner(ctx, tx, ct, fm)
	}
	h.tr = tr
	h.t.Cleanup(func() { _ = tr.Close() })
}

// reopen closes the tracker and opens a new one on the same store, as a
// restart does.
func (h *harness) reopen() {
	h.t.Helper()
	if err := h.tr.Close(); err != nil {
		h.t.Fatal(err)
	}
	h.open()
}

func (h *harness) publish(env *envelope.Envelope) {
	h.mu.Lock()
	h.published = append(h.published, env)
	h.mu.Unlock()
}

func (h *harness) envelopes() []*envelope.Envelope {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*envelope.Envelope(nil), h.published...)
}

// track makes origins the tracked set and confirms them, as Run's next
// maintenance round does.
func (h *harness) track(origins ...string) {
	h.tr.SetTracked(origins)
	h.tr.addWanted(h.ctx)
}

// observe reports tx as broadcast by this node and runs the work it queues.
func (h *harness) observe(tx *transaction.Transaction) {
	h.watch.Observe(tx)
	h.drain()
}

// drain runs every queued candidate as Run does.
func (h *harness) drain() {
	for {
		select {
		case c := <-h.tr.queue:
			if h.tr.process(h.ctx, c) {
				h.tr.follow(h.ctx, c.origin)
			}
		default:
			return
		}
	}
}

// fund returns a mined transaction paying sats to the wallet.
func (h *harness) fund(sats uint64) *transaction.Transaction {
	tx := h.w.Fund(ordtracktest.Out{Sats: sats})
	h.chain.Mine(tx)
	h.store.Add(tx)
	return tx
}

// mint returns a mined transaction whose output 0 is a new origin inscribed
// with body.
func (h *harness) mint(body string) *transaction.Transaction {
	f := h.fund(100_000)
	o := h.w.Spend(h.t, []ordtracktest.In{{Tx: f}}, h.inscribed(body), ordtracktest.Out{Sats: 90_000})
	h.chain.Mine(o)
	h.store.Add(o)
	return o
}

func (h *harness) inscribed(body string) ordtracktest.Out {
	return ordtracktest.Out{Sats: 1, Script: h.w.Inscription("text/plain", []byte(body))}
}

func plain() ordtracktest.Out { return ordtracktest.Out{Sats: 1} }

// move spends the token at prev's output vout, then a fresh mined funding
// input, into out and change. The token's sat lands in out: a transfer when
// out holds 1 sat, an end otherwise. It is stored unmined.
func (h *harness) move(prev *transaction.Transaction, vout uint32, out ordtracktest.Out) *transaction.Transaction {
	return h.moveBy(h.w, prev, vout, out)
}

func (h *harness) moveBy(w *ordtracktest.Wallet, prev *transaction.Transaction, vout uint32, out ordtracktest.Out) *transaction.Transaction {
	f := h.fund(10_000)
	tx := w.Spend(h.t, []ordtracktest.In{{Tx: prev, Vout: vout}, {Tx: f}}, out, ordtracktest.Out{Sats: 10_000 - out.Sats})
	h.store.Add(tx)
	return tx
}

// burn spends a funding input, then the token at prev's output vout, into
// outputs worth less than the funding input, so no output reaches the
// token's sat. It is stored unmined.
func (h *harness) burn(prev *transaction.Transaction, vout uint32) *transaction.Transaction {
	f := h.fund(10_000)
	tx := h.w.Spend(h.t, []ordtracktest.In{{Tx: f}, {Tx: prev, Vout: vout}}, ordtracktest.Out{Sats: 9_000})
	h.store.Add(tx)
	return tx
}

func op(tx *transaction.Transaction, vout uint32) string {
	return outpointString(tx.TxID().String(), vout)
}

func (h *harness) tip(origin string) string {
	h.tr.mu.Lock()
	defer h.tr.mu.Unlock()
	if ch := h.tr.chains[origin]; ch != nil {
		return ch.tip.Outpoint
	}
	return ""
}

func (h *harness) latest(origin string) string {
	h.t.Helper()
	l, err := h.tr.Latest(origin)
	if err != nil {
		h.t.Fatal(err)
	}
	return l
}

// version is origin's version seq, failing the test on an error.
func (h *harness) version(origin string, seq int) (string, bool) {
	h.t.Helper()
	outpoint, pending, err := h.tr.ResolveVersion(origin, seq)
	if err != nil {
		h.t.Fatalf("version %d of %s: %v", seq, origin, err)
	}
	return outpoint, pending
}

func (h *harness) stat(name string) int64 { return h.tr.Stats()[name] }

func (h *harness) wantTip(origin, want string) {
	h.t.Helper()
	if got := h.tip(origin); got != want {
		h.t.Fatalf("tip of %s = %s, want %s", origin, got, want)
	}
}

func (h *harness) wantLatest(origin, want string, wantPending bool) {
	h.t.Helper()
	got, pending := h.version(origin, -1)
	if got != want || pending != wantPending {
		h.t.Fatalf("latest of %s = %s (pending %v), want %s (pending %v)", origin, got, pending, want, wantPending)
	}
	if l := h.latest(origin); l != want {
		h.t.Fatalf("Latest(%s) = %s, want %s", origin, l, want)
	}
}
