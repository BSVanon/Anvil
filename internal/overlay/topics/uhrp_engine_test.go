package topics_test

// Engine-level coverage: these tests drive real
// BRC-26 UHRP transactions through the actual go-overlay-services engine
// (v3engine.New, Anvil's production wiring), not just Admit in isolation —
// confirming the full engine path rather than lookup-only behavior. Package
// topics_test lets this file import
// v3engine (which itself imports topics) with no cycle. The two-tx
// construction (funded advert; real signed spend of it) uses the same
// production transaction flow. overlaytest.SpendingTx exists
// because go-sdk v1.7's spv.Verify now requires every unmined tx to have a
// real, spendable input (see that package's doc).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

// The test-engine helper wires a real engine.Engine the same way
// v3engine's own engine_test.go does (newTestEngine there, unexported —
// this package can't reach it, so it's a faithful duplicate): tmp-dir
// LevelDB instances plus a headers test store with PoW validation off.
func newFixPassTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	root := t.TempDir()

	storageDB, err := leveldb.OpenFile(filepath.Join(root, "storage-ldb"), nil)
	if err != nil {
		t.Fatalf("open storage db: %v", err)
	}
	t.Cleanup(func() { _ = storageDB.Close() })

	lookupDB, err := leveldb.OpenFile(filepath.Join(root, "lookup-ldb"), nil)
	if err != nil {
		t.Fatalf("open lookup db: %v", err)
	}
	t.Cleanup(func() { _ = lookupDB.Close() })

	hdrStore, err := headers.NewTestStore(filepath.Join(root, "headers"))
	if err != nil {
		t.Fatalf("open headers store: %v", err)
	}
	t.Cleanup(func() { _ = hdrStore.Close() })
	// Every test here spends overlaytest.FundingTx via SpendingTx;
	// SeedFundingBlock is the documented required pairing so the headers
	// store (this engine's ChainTracker) accepts FundingTx's BUMP.
	overlaytest.SeedFundingBlock(t, hdrStore)

	eng, err := v3engine.New(&v3engine.Config{
		Storage:      anvilstorage.New(storageDB),
		HeadersStore: hdrStore,
		LookupDB:     lookupDB,
		HostingURL:   "https://anvil.fixpass.test",
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	return eng
}

// freshBRC26Advert is a signed, lockable BRC-26 UHRP advertisement plus
// everything needed to later unlock (spend/revoke) the same output —
// the PushDrop+wallet pairing a revocation needs, kept alongside the
// script so one builder serves every test in this file.
type freshBRC26Advert struct {
	script *script.Script
	pd     *pushdrop.PushDrop
	proto  wallet.Protocol
	party  wallet.Counterparty
}

// buildFreshBRC26Advert signs with forSelf=true, matching real canonical
// producers (overlays/uhrp-server-basic createUHRPAdvertisement.ts) —
// see uhrp_brc26_test.go's buildUHRPBRC26Script comment for why this is
// load-bearing, not cosmetic.
func buildFreshBRC26Advert(t *testing.T, hash []byte, url string) freshBRC26Advert {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "uhrp advertisement"}
	party := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}
	fields := [][]byte{
		priv.PubKey().Compressed(),
		hash,
		[]byte(url),
		util.VarInt(2000000000).Bytes(),
		util.VarInt(10).Bytes(),
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(context.Background(), fields, proto, "1", party, true, true, pushdrop.LockBefore)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return freshBRC26Advert{script: s, pd: pd, proto: proto, party: party}
}

// submitUHRPTx wraps tx in a V1 BEEF and submits it to tm_uhrp, failing
// the test on any Submit error.
func submitUHRPTx(t *testing.T, eng *engine.Engine, tx *transaction.Transaction) overlay.Steak {
	t.Helper()
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	beefBytes, err := beef.Bytes()
	if err != nil {
		t.Fatalf("beef.Bytes: %v", err)
	}
	steak, err := eng.Submit(context.Background(), overlay.TaggedBEEF{
		Beef:   beefBytes,
		Topics: []string{topics.UHRPTopicName},
	}, engine.SubmitModeHistorical, nil)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return steak
}

// freshHash32 returns a 32-byte content hash distinct per seed byte.
func freshHash32(seed byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed
	}
	return h
}

// TestUHRPEngine_FreshlyBuiltAdvertAdmittedAndResolvable verifies that a
// fresh, non-golden-vector BRC-26 advertisement
// goes through the real engine (admission wiring, storage, and the
// lookup-notify path together), not just UHRPTopicManager.Admit called
// directly.
func TestUHRPEngine_FreshlyBuiltAdvertAdmittedAndResolvable(t *testing.T) {
	eng := newFixPassTestEngine(t)
	hash := freshHash32(0x71)
	hashHex := hex.EncodeToString(hash)

	advert := buildFreshBRC26Advert(t, hash, "https://engine.example.test/x")
	tx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: advert.script, Satoshis: 1000})

	steak := submitUHRPTx(t, eng, tx)
	inst, ok := steak[topics.UHRPTopicName]
	if !ok || inst == nil || len(inst.OutputsToAdmit) != 1 || inst.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected the fresh BRC-26 advert admitted at output 0, got %+v", inst)
	}

	q, err := json.Marshal(topics.UHRPLookupQuery{ContentHash: hashHex})
	if err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	answer, err := eng.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if answer.Type != lookup.AnswerTypeOutputList || len(answer.Outputs) != 1 {
		t.Fatalf("expected the engine to resolve the freshly admitted advert, got type=%s n=%d", answer.Type, len(answer.Outputs))
	}
	if len(answer.Outputs[0].Beef) == 0 {
		t.Fatalf("expected hydrated BEEF, got empty")
	}
}

// TestUHRPEngine_PureRevocationDeletesStorageRow is the direct proof of
// the retention behavior: previously, Admit always retained every
// previous coin, leaving the advert's row "STILL STORED spent=true"
// forever. CoinsToRetain is empty and the
// row is gone.
func TestUHRPEngine_PureRevocationDeletesStorageRow(t *testing.T) {
	ctx := context.Background()
	eng := newFixPassTestEngine(t)
	hash := freshHash32(0x5a)
	hashHex := hex.EncodeToString(hash)

	advert := buildFreshBRC26Advert(t, hash, "https://h.example.test/x")
	advertTx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: advert.script, Satoshis: 1000})

	steak1 := submitUHRPTx(t, eng, advertTx)
	if inst, ok := steak1[topics.UHRPTopicName]; !ok || inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("expected advert admitted, got %+v", inst)
	}

	q, err := json.Marshal(topics.UHRPLookupQuery{ContentHash: hashHex})
	if err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	before, err := eng.Lookup(ctx, &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup before revoke: %v", err)
	}
	if len(before.Outputs) != 1 {
		t.Fatalf("expected the advert resolvable before revocation, got %d outputs", len(before.Outputs))
	}

	// A pure revocation: spend the advert's output with no new
	// UHRP-shaped output anywhere among this tx's outputs — an ordinary
	// OP_TRUE payment.
	rev := transaction.NewTransaction()
	if err := rev.AddInputFrom(advertTx.TxID().String(), 0, advert.script.String(), 1000, nil); err != nil {
		t.Fatalf("AddInputFrom: %v", err)
	}
	rev.Inputs[0].SourceTransaction = advertTx
	payout := script.Script{script.OpTRUE}
	rev.AddOutput(&transaction.TransactionOutput{LockingScript: &payout, Satoshis: 900})
	unlockingScript, err := advert.pd.Unlock(ctx, advert.proto, "1", advert.party, wallet.SignOutputsAll, false).Sign(rev, 0)
	if err != nil {
		t.Fatalf("sign revoke input: %v", err)
	}
	rev.Inputs[0].UnlockingScript = unlockingScript

	steak2 := submitUHRPTx(t, eng, rev)
	revInst, ok := steak2[topics.UHRPTopicName]
	if !ok || revInst == nil || len(revInst.OutputsToAdmit) != 0 {
		t.Fatalf("expected the revocation to admit no new output, got %+v", revInst)
	}
	if len(revInst.CoinsToRetain) != 0 {
		t.Fatalf("expected a pure revocation to retain zero coins, got CoinsToRetain=%v (pre-fix bug: always retained every previous coin)", revInst.CoinsToRetain)
	}

	after, err := eng.Lookup(ctx, &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup after revoke: %v", err)
	}
	if len(after.Outputs) != 0 {
		t.Fatalf("expected the lookup index to drop the revoked advert, got %d outputs", len(after.Outputs))
	}

	// The lookup index dropping the advert was already true pre-fix (engine
	// OutputSpent fires unconditionally). This fix changes the ENGINE'S OWN
	// storage row: confirm it's gone, not "spent=true but still stored"
	// (the pre-fix symptom). FindOutput reports a missing row as an error
	// here, not nil — either shape means "deleted."
	uhrpTopic := topics.UHRPTopicName
	stored, ferr := eng.Storage.FindOutput(ctx, &transaction.Outpoint{Txid: *advertTx.TxID(), Index: 0}, &uhrpTopic, nil, false)
	if ferr == nil && stored != nil {
		t.Fatalf("expected the advert's storage row deleted after a pure revocation, still stored: spent=%v consumedBy=%d", stored.Spent, len(stored.ConsumedBy))
	}
}

// The TS-oracle cross-check for {uhrpUrl} answers (the positive BRC-26
// case plus the LEGACY-format negative case) lives in
// uhrp_engine_oracle_test.go, keeping this file within the package's
// established per-file size norm; no behavior changes between the two files.
