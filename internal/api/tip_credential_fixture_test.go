package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/ordtrack"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/BSVanon/Anvil/internal/spendwatch"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// storeSource is the tracker's fetch and tx-status paths over a test store.
type storeSource struct{ s *ordtracktest.Store }

func (a storeSource) Tx(ctx context.Context, txid string) (*transaction.Transaction, error) {
	return a.s.Tx(ctx, txid)
}

func (a storeSource) Status(_ context.Context, txid string) (ordtrack.Status, error) {
	known, mined, height := a.s.Mined(txid)
	return ordtrack.Status{Known: known, Mined: mined, Height: height}, nil
}

// storeRaw is the content server's P2P fetch over a test store.
type storeRaw struct{ s *ordtracktest.Store }

func (a storeRaw) FetchRawTx(txid string) (string, error) {
	tx, err := a.s.Tx(context.Background(), txid)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tx.Bytes()), nil
}

// countingChain counts the merkle roots the tracker's SPV checks look up.
type countingChain struct {
	*ordtracktest.Chain
	roots atomic.Int64
}

func (c *countingChain) IsValidRootForHeight(ctx context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	c.roots.Add(1)
	return c.Chain.IsValidRootForHeight(ctx, root, height)
}

// countingCred counts the tip updates the route asks the tracker to verify.
type countingCred struct {
	TipCredential
	verifies atomic.Int64
}

func (c *countingCred) VerifyTipUpdate(ctx context.Context, n *beefnorm.BEEF, origin, tip string) (func(), error) {
	c.verifies.Add(1)
	return c.TipCredential.VerifyTipUpdate(ctx, n, origin, tip)
}

// tipServer is a node whose validator follows chain. price > 0 makes it
// charge for /broadcast; token "" leaves it without an auth token.
func tipServer(t *testing.T, chain chaintracker.ChainTracker, token string, price int, raw storeRaw) *Server {
	t.Helper()
	hs, err := headers.NewTestStore(filepath.Join(t.TempDir(), "headers"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	ps, err := spv.NewProofStore(filepath.Join(t.TempDir(), "proofs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })
	edir, _ := os.MkdirTemp("", "anvil-api-envs-*")
	t.Cleanup(func() { os.RemoveAll(edir) })
	es, _ := envelope.NewStore(edir, 3600, 65536)
	t.Cleanup(func() { es.Close() })
	srv := NewServer(ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: es,
		Validator: spv.NewValidator(chain), Broadcaster: txrelay.NewBroadcaster(txrelay.NewMempool(), nil, quietLog),
		AuthToken: token, Logger: quietLog, TrustProxy: true, P2PTxSource: raw,
	})
	if price > 0 {
		srv.paymentGate = testGate(t, price)
		srv.mux = http.NewServeMux()
		srv.routes()
	}
	return srv
}

// tipFixture is a node tracking one origin, beside the same node without
// tracking.
type tipFixture struct {
	t       *testing.T
	w       *ordtracktest.Wallet
	chain   *ordtracktest.Chain
	counted *countingChain
	store   *ordtracktest.Store
	tr      *ordtrack.Tracker
	cred    *countingCred
	srv     *Server // tracking
	plain   *Server // the same node, never told about tracking
	origin  *transaction.Transaction
}

func newTipFixture(t *testing.T, token string, price int) *tipFixture {
	t.Helper()
	f := &tipFixture{t: t, w: ordtracktest.NewWallet(t), chain: ordtracktest.NewChain(), store: ordtracktest.NewStore()}
	f.counted = &countingChain{Chain: f.chain}
	woc := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(woc.Close)
	watch := spendwatch.New(spendwatch.Config{WoCBase: woc.URL, RequestGap: time.Microsecond, Logger: quietLog})
	tr, err := ordtrack.New(ordtrack.Config{
		Path: filepath.Join(t.TempDir(), "ordtrack"), Source: storeSource{f.store}, Chain: f.counted, Watcher: watch, Logger: quietLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tr.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; _ = tr.Close() })
	f.tr = tr

	f.origin = f.mint("v0")
	tr.SetTracked([]string{op(f.origin, 0)})
	for deadline := time.Now().Add(5 * time.Second); !tr.Active(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the origin was not confirmed")
		}
	}
	f.srv = tipServer(t, f.chain, token, price, storeRaw{f.store})
	f.cred = &countingCred{TipCredential: tr}
	f.srv.SetTipCredential(f.cred, tr.Stats)
	f.srv.broadcaster.SetObserver(func(tx *transaction.Transaction, beef []byte) {
		tr.NoteBroadcast(tx, beef)
		watch.Observe(tx)
	})
	f.plain = tipServer(t, f.chain, token, price, storeRaw{f.store})
	return f
}

func op(tx *transaction.Transaction, vout uint32) string {
	return tx.TxID().String() + "_" + strconv.FormatUint(uint64(vout), 10)
}

func (f *tipFixture) fund(sats uint64) *transaction.Transaction {
	tx := f.w.Fund(ordtracktest.Out{Sats: sats})
	f.chain.Mine(tx)
	f.store.Add(tx)
	return tx
}

func (f *tipFixture) mint(body string) *transaction.Transaction {
	fund := f.fund(100_000)
	o := f.w.Spend(f.t, []ordtracktest.In{{Tx: fund}}, f.inscribed(body), ordtracktest.Out{Sats: 90_000})
	f.chain.Mine(o)
	f.store.Add(o)
	return o
}

func (f *tipFixture) inscribed(body string) ordtracktest.Out {
	return ordtracktest.Out{Sats: 1, Script: f.w.Inscription("text/plain", []byte(body))}
}

// move spends prev's output vout, then a mined funding input, into out and
// change, signed by w.
func (f *tipFixture) move(w *ordtracktest.Wallet, prev *transaction.Transaction, vout uint32, out ordtracktest.Out) *transaction.Transaction {
	fund := f.fund(10_000)
	tx := w.Spend(f.t, []ordtracktest.In{{Tx: prev, Vout: vout}, {Tx: fund}}, out, ordtracktest.Out{Sats: 10_000 - out.Sats})
	f.store.Add(tx)
	return tx
}

func (f *tipFixture) tip() string {
	out, _, err := f.tr.ResolveVersion(op(f.origin, 0), -1)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

// post sends body to POST /broadcast with the given headers.
func post(srv *Server, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/broadcast", bytes.NewReader(body))
	req.Host = "localhost"
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func broadcastStatus(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp BroadcastResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return resp.Status
}
