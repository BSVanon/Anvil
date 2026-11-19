package v3engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

// stallingStorage sits between the engine's detached view of storage and the
// real store. arm makes the next call to one method run a hold function, so a
// test can let the submit deadline expire while that call is in flight.
// MarkUTXOsAsSpent runs its hold after its write; the other held methods run
// it before they delegate. Every other method passes straight through.
type stallingStorage struct {
	engine.Storage

	mu     sync.Mutex
	method string
	hold   func()
}

// arm makes the next call to method run hold.
func (s *stallingStorage) arm(method string, hold func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.method, s.hold = method, hold
}

// stallIf runs the armed hold, once, if it is armed for method.
func (s *stallingStorage) stallIf(method string) {
	s.mu.Lock()
	hold := s.hold
	if s.method == method {
		s.method, s.hold = "", nil
	} else {
		hold = nil
	}
	s.mu.Unlock()
	if hold != nil {
		hold()
	}
}

// DoesAppliedTransactionExist is the engine's first storage read in a submit.
func (s *stallingStorage) DoesAppliedTransactionExist(ctx context.Context, tx *overlay.AppliedTransaction) (bool, error) {
	s.stallIf("DoesAppliedTransactionExist")
	return s.Storage.DoesAppliedTransactionExist(ctx, tx)
}

// MarkUTXOsAsSpent is the engine's first write in a submit that spends an
// admitted output.
func (s *stallingStorage) MarkUTXOsAsSpent(ctx context.Context, outpoints []*transaction.Outpoint, topic string, spendTxid *chainhash.Hash) error {
	err := s.Storage.MarkUTXOsAsSpent(ctx, outpoints, topic, spendTxid)
	s.stallIf("MarkUTXOsAsSpent")
	return err
}

// InsertOutputs stores one topic's admitted outputs during the commit.
func (s *stallingStorage) InsertOutputs(ctx context.Context, topic string, txid *chainhash.Hash, outputs []uint32, outpointsConsumed []*transaction.Outpoint, beef *transaction.Beef, ancillaryTxids []*chainhash.Hash) error {
	s.stallIf("InsertOutputs")
	return s.Storage.InsertOutputs(ctx, topic, txid, outputs, outpointsConsumed, beef, ancillaryTxids)
}

// InsertAppliedTransaction is the last write of one topic's commit.
func (s *stallingStorage) InsertAppliedTransaction(ctx context.Context, tx *overlay.AppliedTransaction) error {
	s.stallIf("InsertAppliedTransaction")
	return s.Storage.InsertAppliedTransaction(ctx, tx)
}

// stallingEngine is an engine built by New over a stallingStorage that wraps a
// real anvilstorage.Storage. store and the two databases let a test read the
// state a submit left without going through the engine.
type stallingEngine struct {
	eng       *engine.Engine
	stall     *stallingStorage
	store     *anvilstorage.Storage
	storageDB *leveldb.DB
	lookupDB  *leveldb.DB
}

// newStallingEngine wires the engine as newTestEngine does, with a
// stallingStorage under the engine's view of storage.
func newStallingEngine(t *testing.T) *stallingEngine {
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
	storageDB, lookupDB := open("storage-ldb"), open("lookup-ldb")
	hdrStore, err := headers.NewTestStore(filepath.Join(root, "headers"))
	if err != nil {
		t.Fatalf("open headers store: %v", err)
	}
	t.Cleanup(func() { _ = hdrStore.Close() })
	overlaytest.SeedFundingBlock(t, hdrStore)

	store := anvilstorage.New(storageDB)
	stall := &stallingStorage{Storage: store}
	eng, err := New(&Config{
		Storage:         store,
		HeadersStore:    hdrStore,
		LookupDB:        lookupDB,
		HostingURL:      "https://anvil.test",
		storageOverride: stall,
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	return &stallingEngine{eng: eng, stall: stall, store: store, storageDB: storageDB, lookupDB: lookupDB}
}

// commitTopics are the two topics the spend is submitted to, committed by the
// engine in this order.
var commitTopics = []string{topics.DEXSwapTopicName, topics.UHRPTopicName}

// commitFixture is the history the mid-commit tests submit. offer puts a DEX
// swap offer at vout 0. spend spends offer:0, re-offers at vout 0 and
// advertises uhrpHash at vout 2, so its submit to commitTopics marks an
// admitted input spent and deletes it, then stores, indexes and records the
// transaction in tm_dex_swap and then in tm_uhrp.
type commitFixture struct {
	offer, spend         *transaction.Transaction
	offerBEEF, spendBEEF []byte
	uhrpHash             string
}

func newCommitFixture(t *testing.T) *commitFixture {
	t.Helper()
	offer := overlaytest.SpendingTx(t, offerOutputs(t, 1_000)...)
	spend := transaction.NewTransaction()
	spend.AddInputFromTx(offer, 0, nil)
	spend.Inputs[0].UnlockingScript = &script.Script{}
	for _, out := range offerOutputs(t, 500) {
		spend.AddOutput(out)
	}
	hash := strings.Repeat("c4", 32)
	spend.AddOutput(uhrpOutput(t, hash))
	return &commitFixture{
		offer:     offer,
		spend:     spend,
		offerBEEF: encodeFixtureBEEF(t, offer, true),
		spendBEEF: encodeFixtureBEEF(t, spend, true),
		uhrpHash:  hash,
	}
}

// offerOutputs returns a DEX swap offer worth sats, locked with OP_TRUE so the
// next transaction spends it with an empty unlocking script, followed by the
// dex.swap.offer metadata output that points at it. The offer must be the
// transaction's vout 0.
func offerOutputs(t *testing.T, sats uint64) []*transaction.TransactionOutput {
	t.Helper()
	entry, err := json.Marshal(topics.DEXSwapEntry{
		Maker:      "02" + strings.Repeat("11", 32),
		Offering:   json.RawMessage(`{"sats":1000}`),
		Requesting: json.RawMessage(`{"sats":2000}`),
		OfferVout:  0,
	})
	if err != nil || len(entry) > 0xff {
		t.Fatalf("DEX swap entry: %d bytes, %v", len(entry), err)
	}
	meta := []byte{0x00, 0x6a, byte(len(topics.DEXSwapProtocol))}
	meta = append(meta, topics.DEXSwapProtocol...)
	meta = append(meta, 1, byte(topics.DEXSwapVersion), 0x4c, byte(len(entry)))
	meta = append(meta, entry...)
	offerScript := script.Script{script.OpTRUE}
	metaScript := script.Script(meta)
	return []*transaction.TransactionOutput{
		{LockingScript: &offerScript, Satoshis: sats},
		{LockingScript: &metaScript, Satoshis: 0},
	}
}

// uhrpOutput returns a BRC-26 UHRP advertisement of the 32-byte hashHex, laid
// out as buildUHRPTaggedBEEF lays it out.
func uhrpOutput(t *testing.T, hashHex string) *transaction.TransactionOutput {
	t.Helper()
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != 32 {
		t.Fatalf("bad UHRP hash %q: %v", hashHex, err)
	}
	b := []byte{0x00, 0x6a, byte(len(topics.UHRPProtocolID))}
	b = append(b, topics.UHRPProtocolID...)
	b = append(b, byte(len(hash)))
	b = append(b, hash...)
	for _, field := range []string{"https://example.test/commit", "image/png"} {
		b = append(b, byte(len(field)))
		b = append(b, field...)
	}
	s := script.Script(b)
	return &transaction.TransactionOutput{LockingScript: &s, Satoshis: 0}
}

// admitOffer submits fx.offer to tm_dex_swap and fails unless its vout 0 is
// admitted.
func admitOffer(t *testing.T, eng *engine.Engine, fx *commitFixture) {
	t.Helper()
	steak, err := eng.Submit(context.Background(), overlay.TaggedBEEF{
		Beef:   fx.offerBEEF,
		Topics: []string{topics.DEXSwapTopicName},
	}, engine.SubmitModeCurrent, nil)
	if err != nil {
		t.Fatalf("submit the offer: %v", err)
	}
	if ai := steak[topics.DEXSwapTopicName]; ai == nil || len(ai.OutputsToAdmit) != 1 || ai.OutputsToAdmit[0] != 0 {
		t.Fatalf("the offer's vout 0 was not admitted: %+v", ai)
	}
}

// assertSpendCommitted fails unless fx.spend's submit is fully committed in
// both topics: offer:0 gone from tm_dex_swap (it was marked spent and, as
// tm_dex_swap keeps no spent coins, deleted), spend:0 and spend:2 stored and
// unspent, the spend recorded as applied to both topics, and each lookup
// service indexing exactly the new output.
func assertSpendCommitted(t *testing.T, se *stallingEngine, fx *commitFixture) {
	t.Helper()
	ctx := context.Background()
	dex, uhrp := topics.DEXSwapTopicName, topics.UHRPTopicName
	spent := &transaction.Outpoint{Txid: *fx.offer.TxID(), Index: 0}
	reoffer := &transaction.Outpoint{Txid: *fx.spend.TxID(), Index: 0}
	advert := &transaction.Outpoint{Txid: *fx.spend.TxID(), Index: 2}

	if out, err := se.store.FindOutput(ctx, spent, &dex, nil, false); !errors.Is(err, engine.ErrNotFound) {
		t.Errorf("the spent offer %s is still stored: %+v, %v", spent, out, err)
	}
	for _, c := range []struct {
		op    *transaction.Outpoint
		topic string
	}{{reoffer, dex}, {advert, uhrp}} {
		out, err := se.store.FindOutput(ctx, c.op, &c.topic, nil, false)
		if err != nil || out == nil || out.Spent {
			t.Errorf("%s in %s: want a stored unspent output, got %+v, %v", c.op, c.topic, out, err)
		}
		applied, err := se.store.DoesAppliedTransactionExist(ctx, &overlay.AppliedTransaction{Txid: fx.spend.TxID(), Topic: c.topic})
		if err != nil || !applied {
			t.Errorf("the spend is not recorded as applied to %s: %v, %v", c.topic, applied, err)
		}
	}
	uhrpQuery, err := json.Marshal(topics.UHRPLookupQuery{ContentHash: fx.uhrpHash})
	if err != nil {
		t.Fatalf("marshal UHRP query: %v", err)
	}
	assertIndexes(t, se.eng, topics.DEXSwapLookupServiceName, []byte(`{"list":"all"}`), reoffer)
	assertIndexes(t, se.eng, topics.UHRPLookupServiceName, uhrpQuery, advert)
}

// assertIndexes fails unless the registered lookup service answers query with
// exactly want.
func assertIndexes(t *testing.T, eng *engine.Engine, service string, query []byte, want *transaction.Outpoint) {
	t.Helper()
	svc, ok := eng.GetLookupService(service)
	if !ok {
		t.Fatalf("no lookup service %s", service)
	}
	answer, err := svc.Lookup(context.Background(), &lookup.LookupQuestion{Service: service, Query: query})
	if err != nil {
		t.Errorf("%s lookup: %v", service, err)
		return
	}
	var got []string
	for _, f := range answer.Formulas {
		got = append(got, f.Outpoint.String())
	}
	if len(got) != 1 || got[0] != want.String() {
		t.Errorf("%s indexes %v, want only %s", service, got, want)
	}
}

// dbDigest summarises every key and value in db: two digests are equal only
// when the database holds exactly the same records.
func dbDigest(t *testing.T, db *leveldb.DB) string {
	t.Helper()
	h := sha256.New()
	it := db.NewIterator(nil, nil)
	defer it.Release()
	n := 0
	for it.Next() {
		for _, b := range [][]byte{it.Key(), it.Value()} {
			_, _ = h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
			_, _ = h.Write(b)
		}
		n++
	}
	if err := it.Error(); err != nil {
		t.Fatalf("iterate database: %v", err)
	}
	return fmt.Sprintf("%d records, sha256 %x", n, h.Sum(nil))
}

// stateDigest is dbDigest over the store's and the lookup services' databases.
func stateDigest(t *testing.T, se *stallingEngine) string {
	t.Helper()
	return "store " + dbDigest(t, se.storageDB) + "; lookups " + dbDigest(t, se.lookupDB)
}

// countingTracker is a SLAP tracker that answers every lookup with an empty
// output list and counts the requests it receives.
type countingTracker struct {
	URL  string
	hits atomic.Int64
}

func newCountingTracker(t *testing.T) *countingTracker {
	t.Helper()
	ct := &countingTracker{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct.hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"output-list","outputs":[]}`)
	}))
	t.Cleanup(srv.Close)
	ct.URL = srv.URL
	return ct
}
