package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/content"
	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/ordtrack"
	"github.com/BSVanon/Anvil/internal/ordtrack/ordtracktest"
	"github.com/BSVanon/Anvil/internal/spendwatch"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// chainFetcher is the tx-status path and the proof fetch over a test store.
type chainFetcher struct {
	store *ordtracktest.Store
	beef  map[string][]byte // FetchBEEF's answer, when set
	err   error             // TxStatus's error, when set
}

func (f *chainFetcher) TxStatus(txid string) (*spv.TxStatusResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	known, mined, height := f.store.Mined(txid)
	return &spv.TxStatusResult{Found: known, Mined: mined, BlockHeight: height}, nil
}

func (f *chainFetcher) FetchBEEF(txid string) ([]byte, string, error) {
	if b, ok := f.beef[txid]; ok {
		return b, spv.BEEFSourceWoC, nil
	}
	tx, err := f.store.Tx(context.Background(), txid)
	if err != nil || tx.MerklePath == nil {
		return nil, "", errors.New("no proof")
	}
	b, err := tx.AtomicBEEF(false)
	return b, spv.BEEFSourceWoC, err
}

// rawSource is the content server's P2P fetch over a test store.
type rawSource struct{ s *ordtracktest.Store }

func (r rawSource) FetchRawTx(txid string) (string, error) {
	tx, err := r.s.Tx(context.Background(), txid)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tx.Bytes()), nil
}

// trackingNode is a node with an auth token over a test chain, and the
// configuration and dependencies tracking takes, tracking nothing yet.
type trackingNode struct {
	t     *testing.T
	w     *ordtracktest.Wallet
	chain *ordtracktest.Chain
	store *ordtracktest.Store
	srv   *api.Server
	envs  *envelope.Store
	key   *ec.PrivateKey
	cfg   *config.Config
	deps  trackingDeps
}

func newTrackingNode(t *testing.T) *trackingNode {
	t.Helper()
	n := &trackingNode{t: t, w: ordtracktest.NewWallet(t), chain: ordtracktest.NewChain(), store: ordtracktest.NewStore()}
	hs, err := headers.NewTestStore(filepath.Join(t.TempDir(), "headers"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hs.Close() })
	ps, err := spv.NewProofStore(filepath.Join(t.TempDir(), "proofs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	if n.envs, err = envelope.NewStore(filepath.Join(t.TempDir(), "envelopes"), 3600, 65536); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.envs.Close() })
	if n.key, err = ec.NewPrivateKey(); err != nil {
		t.Fatal(err)
	}
	bc := txrelay.NewBroadcaster(txrelay.NewMempool(), nil, quietLogger)
	n.srv = api.NewServer(api.ServerConfig{
		HeaderStore: hs, ProofStore: ps, EnvelopeStore: n.envs, Validator: spv.NewValidator(n.chain),
		Broadcaster: bc, AuthToken: "test-token", Logger: quietLogger, P2PTxSource: rawSource{n.store},
	})
	n.cfg = &config.Config{}
	n.cfg.Node.DataDir = t.TempDir()
	n.cfg.Content = config.ContentConfig{MaxTrackedOrigins: 10, MaxWatchedOutpoints: 100, SpendPollInterval: 600, TipPendingTimeout: 86400}
	n.cfg.Gateway.RootMaxAge = 60
	n.cfg.Envelopes.MaxDurableSize = 65536
	n.deps = trackingDeps{n.chain, ps, &chainFetcher{store: n.store}, bc, nil, n.envs, n.key}
	return n
}

// start starts tracking against a spend watch that finds every outpoint
// unspent.
func (n *trackingNode) start() (*ordtrack.Tracker, func()) {
	n.t.Helper()
	woc := httptest.NewServer(http.NotFoundHandler())
	n.t.Cleanup(woc.Close)
	tr, stop := startTracking(context.Background(), n.cfg, n.srv, quietLogger, n.deps, spendwatch.Config{WoCBase: woc.URL, RequestGap: time.Microsecond})
	n.t.Cleanup(stop)
	return tr, stop
}

func op(tx *transaction.Transaction, vout uint32) string {
	return tx.TxID().String() + "_" + strconv.FormatUint(uint64(vout), 10)
}

func (n *trackingNode) fund(sats uint64) *transaction.Transaction {
	tx := n.w.Fund(ordtracktest.Out{Sats: sats})
	n.chain.Mine(tx)
	n.store.Add(tx)
	return tx
}

func (n *trackingNode) inscribed(body string) ordtracktest.Out {
	return ordtracktest.Out{Sats: 1, Script: n.w.Inscription("text/plain", []byte(body))}
}

func (n *trackingNode) mint(body string) *transaction.Transaction {
	o := n.w.Spend(n.t, []ordtracktest.In{{Tx: n.fund(100_000)}}, n.inscribed(body), ordtracktest.Out{Sats: 90_000})
	n.chain.Mine(o)
	n.store.Add(o)
	return o
}

// move spends prev's output vout and a mined funding input into out.
func (n *trackingNode) move(prev *transaction.Transaction, vout uint32, out ordtracktest.Out) *transaction.Transaction {
	tx := n.w.Spend(n.t, []ordtracktest.In{{Tx: prev, Vout: vout}, {Tx: n.fund(10_000)}}, out, ordtracktest.Out{Sats: 10_000 - out.Sats})
	n.store.Add(tx)
	return tx
}

func (n *trackingNode) do(method, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Host = "localhost"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	n.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (n *trackingNode) tracking() (map[string]int64, bool) {
	var out map[string]json.RawMessage
	if err := json.Unmarshal(n.do(http.MethodGet, "/stats", nil, nil).Body.Bytes(), &out); err != nil {
		n.t.Fatal(err)
	}
	raw, ok := out["tracking"]
	if !ok {
		return nil, false
	}
	var stats map[string]int64
	if err := json.Unmarshal(raw, &stats); err != nil {
		n.t.Fatal(err)
	}
	return stats, true
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func TestTrackingServesVersionsAndTakesTipUpdates(t *testing.T) {
	n := newTrackingNode(t)
	origin := n.mint("v0")
	n.cfg.Content.TrackOrigins = []string{op(origin, 0)}
	tr, stop := n.start()
	if tr == nil {
		t.Fatal("tracking did not start")
	}
	waitFor(t, "the origin to be confirmed", tr.Active)
	seq := "/content/" + op(origin, 0) + "?seq="

	rec := n.do(http.MethodGet, seq+"0", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "v0" || rec.Header().Get(content.OutpointHeader) != op(origin, 0) ||
		rec.Header().Get("Cache-Control") != content.ImmutableCacheControl {
		t.Fatalf("seq 0: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}

	// A tip update needs no token; the version it adds is served at once.
	v1 := n.move(origin, 0, n.inscribed("v1"))
	if rec := n.do(http.MethodPost, "/broadcast", ordtracktest.AtomicBEEF(t, v1), map[string]string{"Content-Type": "application/octet-stream"}); rec.Code != http.StatusOK {
		t.Fatalf("tip update: %d %s", rec.Code, rec.Body.String())
	}
	rec = n.do(http.MethodGet, seq+"-1", nil, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "v1" || rec.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("latest: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}

	// The tip is published as a signed envelope.
	envs, err := n.envs.QueryByTopic(ordtrack.TipTopic, 10)
	if err != nil || len(envs) != 1 || envs[0].Pubkey != hex.EncodeToString(n.key.PubKey().Compressed()) ||
		!strings.Contains(envs[0].Payload, `"newTip":"`+op(v1, 0)+`"`) || envs[0].Validate() != nil {
		t.Fatalf("published %v, %v", envs, err)
	}
	if stats, ok := n.tracking(); !ok || stats["broadcast_tip_credential_used"] != 1 || stats["ordtrack_origins"] != 1 {
		t.Fatalf("stats %v", stats)
	}

	// A token broadcast reaches the tracker through the broadcaster.
	v2 := n.move(v1, 0, n.inscribed("v2"))
	if rec := n.do(http.MethodPost, "/broadcast", ordtracktest.AtomicBEEF(t, v2), map[string]string{"Content-Type": "application/octet-stream", "X-Anvil-Auth": "test-token"}); rec.Code != http.StatusOK {
		t.Fatalf("token broadcast: %d %s", rec.Code, rec.Body.String())
	}
	waitFor(t, "the token broadcast to be followed", func() bool {
		latest, _, _ := tr.ResolveVersion(op(origin, 0), -1)
		return latest == op(v2, 0)
	})

	// Stopped, the node answers as one without tracking.
	stop()
	if rec := n.do(http.MethodGet, seq+"0", nil, nil); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), content.ErrNotTracked.Error()) {
		t.Fatalf("after stop: %d %q", rec.Code, rec.Body.String())
	}
	if _, ok := n.tracking(); ok {
		t.Fatal("tracking stats after stop")
	}
}

// A node that tracks nothing opens, starts and hooks nothing.
func TestNothingTrackedStartsNothing(t *testing.T) {
	n := newTrackingNode(t)
	if tr, _ := n.start(); tr != nil {
		t.Fatal("tracking started with nothing to track")
	}
	if tr := wireTracking(n.cfg, n.srv, quietLogger, n.deps); tr != nil {
		t.Fatal("wireTracking started with nothing to track")
	}
	if _, err := os.Stat(filepath.Join(n.cfg.Node.DataDir, "ordtrack")); !os.IsNotExist(err) {
		t.Fatalf("a version store was opened: %v", err)
	}
	if _, ok := n.tracking(); ok {
		t.Fatal("tracking stats on a node that tracks nothing")
	}
	origin := n.mint("v0")
	if rec := n.do(http.MethodGet, "/content/"+op(origin, 0)+"?seq=0", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("?seq: %d", rec.Code)
	}
	// Without its stores, a gateway does not track either.
	n.cfg.Gateway.Enabled = true
	if tr := wireTracking(n.cfg, n.srv, quietLogger, trackingDeps{}); tr != nil {
		t.Fatal("tracking started without its stores")
	}
}

// A gateway tracks the origins its sites file allows.
func TestGatewayTracksTheSitesFilesOrigins(t *testing.T) {
	n := newTrackingNode(t)
	origin := n.mint("site")
	n.cfg.Gateway.Enabled = true
	n.cfg.Gateway.APIHost = "localhost"
	n.cfg.Gateway.ContentScope = "site"
	n.cfg.Gateway.SitesFile = filepath.Join(t.TempDir(), "sites.conf")
	if err := os.WriteFile(n.cfg.Gateway.SitesFile, []byte("origin "+op(origin, 0)+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	tr, _ := n.start()
	if tr == nil || tr.Active() {
		t.Fatalf("tracker %v before the policy is read", tr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := gatewayHandler(ctx, n.cfg, n.srv, quietLogger, tr)
	waitFor(t, "the sites file's origin to be tracked", tr.Active)
	req := httptest.NewRequest(http.MethodGet, "/content/"+op(origin, 0)+"?seq=-1", nil)
	req.Host = "localhost"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "site" {
		t.Fatalf("api host ?seq=-1: %d %q", rec.Code, rec.Body.String())
	}
}
