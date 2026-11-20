package v3engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// TestDetachedStorage_ReadOnlyRequestsReadsKeepCancellation: for a context
// marked overlayctx.ReadOnly, the eight reads reach the store with the
// caller's cancellation and values, and the nine writes still without the
// cancellation.
func TestDetachedStorage_ReadOnlyRequestsReadsKeepCancellation(t *testing.T) {
	seen := recorder{}
	view := detachedStorage{inner: recordingStorage{seen: seen}}
	ctx := overlayctx.ReadOnly(cancelledCtx())
	reads := map[string]func(){
		"FindOutput":                  func() { _, _ = view.FindOutput(ctx, nil, nil, nil, false) },
		"FindOutputs":                 func() { _, _ = view.FindOutputs(ctx, nil, "", nil, false) },
		"FindOutputsForTransaction":   func() { _, _ = view.FindOutputsForTransaction(ctx, nil, false) },
		"FindUTXOsForTopic":           func() { _, _ = view.FindUTXOsForTopic(ctx, "", 0, 0, false) },
		"DoesAppliedTransactionExist": func() { _, _ = view.DoesAppliedTransactionExist(ctx, nil) },
		"GetLastInteraction":          func() { _, _ = view.GetLastInteraction(ctx, "", "") },
		"FindOutpointsByMerkleState":  func() { _, _ = view.FindOutpointsByMerkleState(ctx, "", 0, 0) },
		"LoadAncillaryBeef":           func() { _ = view.LoadAncillaryBeef(ctx, nil) },
	}
	writes := map[string]func(){
		"InsertOutputs":            func() { _ = view.InsertOutputs(ctx, "", nil, nil, nil, nil, nil) },
		"DeleteOutput":             func() { _ = view.DeleteOutput(ctx, nil, "") },
		"MarkUTXOsAsSpent":         func() { _ = view.MarkUTXOsAsSpent(ctx, nil, "", nil) },
		"UpdateConsumedBy":         func() { _ = view.UpdateConsumedBy(ctx, nil, "", nil) },
		"UpdateTransactionBEEF":    func() { _ = view.UpdateTransactionBEEF(ctx, nil, nil) },
		"UpdateOutputBlockHeight":  func() { _ = view.UpdateOutputBlockHeight(ctx, nil, "", 0, 0) },
		"InsertAppliedTransaction": func() { _ = view.InsertAppliedTransaction(ctx, nil) },
		"UpdateLastInteraction":    func() { _ = view.UpdateLastInteraction(ctx, "", "", 0) },
		"ReconcileMerkleRoot":      func() { _ = view.ReconcileMerkleRoot(ctx, "", 0, nil) },
	}
	names := func(m map[string]func()) (out []string) {
		for name := range m {
			out = append(out, name)
		}
		return out
	}
	iface := reflect.TypeFor[engine.Storage]()
	assertCalls(t, iface, reads, seen, false, names(writes)...)
	assertCalls(t, iface, writes, seen, true, names(reads)...)
}

// slowReads stands beneath the engine's view of storage. Its FindOutput takes
// delay and finds nothing, as a costly read of an output that is gone would,
// and refuses a call whose context has ended, as Anvil's store does on entry.
// It counts the reads that ran, notes when the last began, and counts the
// FindOutput and FindUTXOsForTopic calls whose context was marked read-only.
type slowReads struct {
	*anvilstorage.Storage
	delay  time.Duration
	calls  atomic.Int64
	last   atomic.Int64 // Unix nanoseconds
	marked atomic.Int64
}

func (s *slowReads) FindOutput(ctx context.Context, _ *transaction.Outpoint, _ *string, _ *bool, _ bool) (*engine.Output, error) {
	if overlayctx.IsReadOnly(ctx) {
		s.marked.Add(1)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.last.Store(time.Now().UnixNano())
	s.calls.Add(1)
	time.Sleep(s.delay)
	return nil, nil
}

func (s *slowReads) FindUTXOsForTopic(ctx context.Context, topic string, since float64, limit uint32, includeBEEF bool) ([]*engine.Output, error) {
	if overlayctx.IsReadOnly(ctx) {
		s.marked.Add(1)
	}
	return s.Storage.FindUTXOsForTopic(ctx, topic, since, limit, includeBEEF)
}

// newSlowReadEngine wires the engine as newTestEngine does, with slowReads of
// the given delay beneath the engine's view of storage.
func newSlowReadEngine(t *testing.T, delay time.Duration) (*engine.Engine, *slowReads) {
	t.Helper()
	root := t.TempDir()
	open := func(name string) *leveldb.DB {
		db, err := leveldb.OpenFile(filepath.Join(root, name), nil)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	hdrStore, err := headers.NewTestStore(filepath.Join(root, "headers"))
	if err != nil {
		t.Fatalf("open headers store: %v", err)
	}
	t.Cleanup(func() { _ = hdrStore.Close() })
	overlaytest.SeedFundingBlock(t, hdrStore)
	store := anvilstorage.New(open("storage-ldb"))
	slow := &slowReads{Storage: store, delay: delay}
	eng, err := New(&Config{Storage: store, HeadersStore: hdrStore, LookupDB: open("lookup-ldb"), HostingURL: "https://anvil.test", storageOverride: slow})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	return eng, slow
}

// formulaLookup answers every question with n formulas, so the engine reads n
// outputs in turn to hydrate the answer.
type formulaLookup struct {
	recordingLookup
	n int
}

func (f formulaLookup) Lookup(context.Context, *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	formulas := make([]lookup.LookupFormula, f.n)
	for i := range formulas {
		var txid chainhash.Hash
		binary.LittleEndian.PutUint32(txid[:], uint32(i)+1)
		formulas[i] = lookup.LookupFormula{Outpoint: &transaction.Outpoint{Txid: txid}}
	}
	return &lookup.LookupAnswer{Type: lookup.AnswerTypeFormula, Formulas: formulas}, nil
}

// TestLookup_DisconnectStopsTheReads (cold review round 3 S4): a lookup whose
// answer names 2,000 outputs, each a 10 ms read, stops reading them once its
// client goes away, within about one read, rather than reading on for 20 s
// for nobody.
func TestLookup_DisconnectStopsTheReads(t *testing.T) {
	const n, delay = 2000, 10 * time.Millisecond
	eng, slow := newSlowReadEngine(t, delay)
	eng.RegisterLookupService("ls_formulas", formulaLookup{recordingLookup: recordingLookup{seen: recorder{}}, n: n})
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	ctx, disconnect := context.WithCancel(t.Context())
	defer disconnect()
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url+"/lookup", strings.NewReader(`{"service":"ls_formulas","query":{}}`))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Transport: &http.Transport{}}
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	for end := time.Now().Add(10 * time.Second); slow.calls.Load() < 20; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("the lookup read %d outputs in 10 s", slow.calls.Load())
		}
	}
	at, gone := slow.calls.Load(), time.Now()
	disconnect()
	<-done
	for prev := int64(-1); prev != slow.calls.Load(); time.Sleep(20 * delay) {
		prev = slow.calls.Load()
	}
	after, stopped := slow.calls.Load()-at, time.Unix(0, slow.last.Load()).Add(delay)
	t.Logf("client gone after %d reads: %d more began, the last ended %v after it went (each read %v)", at, after, stopped.Sub(gone), delay)
	if after > 3 || slow.calls.Load() >= n {
		t.Fatalf("%d reads began after the client went, %d of %d in all; want the reads to stop within about one", after, slow.calls.Load(), n)
	}
}

// TestGASPReplies_ReadsAreReadOnly: the two GASP replies hand the engine their
// request's context marked read-only, so their reads stop with their client
// too.
func TestGASPReplies_ReadsAreReadOnly(t *testing.T) {
	eng, slow := newSlowReadEngine(t, 0)
	url := guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
	var txid chainhash.Hash
	txid[0] = 1
	node, _ := json.Marshal(gasp.NodeRequest{GraphID: &transaction.Outpoint{Txid: txid}, Txid: &txid})
	for path, body := range map[string][]byte{
		"/requestSyncResponse":    []byte(`{"version":1,"since":0}`),
		"/requestForeignGASPNode": node,
	} {
		before := slow.marked.Load()
		req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-BSV-Topic", topics.UHRPTopicName)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if slow.marked.Load() == before {
			t.Errorf("%s (answered %d) read the store without the read-only mark", path, resp.StatusCode)
		}
	}
}

// goneLookup is a lookup service during whose work its client goes away: it
// answers once the context it was given has ended.
type goneLookup struct{ recordingLookup }

func (goneLookup) Lookup(ctx context.Context, _ *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	<-ctx.Done()
	return &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList}, nil
}

// TestLookupFor_ClientGoneBeforeTheAnswer: a lookup whose client went away
// while it ran fails with the request's error though the engine answered, so
// the handler does not aggregate an answer for nobody.
func TestLookupFor_ClientGoneBeforeTheAnswer(t *testing.T) {
	eng, _ := newTestEngine(t)
	eng.RegisterLookupService("ls_gone", goneLookup{recordingLookup{seen: recorder{}}})
	ctx, gone := context.WithCancel(t.Context())
	gone()
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/lookup", nil)
	answer, err := lookupFor(r, eng, &lookup.LookupQuestion{Service: "ls_gone", Query: json.RawMessage(`{}`)})
	if !errors.Is(err, context.Canceled) || answer != nil {
		t.Fatalf("a lookup whose client went away: %v, %v; want context.Canceled and no answer", answer, err)
	}
}
