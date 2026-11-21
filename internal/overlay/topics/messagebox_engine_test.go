package topics_test

// Engine-level coverage drives a real MessageBox
// advert through the actual go-overlay-services engine (v3engine.New,
// Anvil's production wiring) rather than just Admit in isolation, and
// confirms a pure revocation deletes the engine's OWN storage row —
// mirroring uhrp_engine_test.go's TestUHRPEngine_PureRevocationDeletesStorageRow
// exactly, reusing its test-engine helper (same package).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestMessageBoxEngine_PureRevocationDeletesStorageRow verifies that after the
// coin-retention correction (CoinsToRetain nil,
// CoinsRemoved built from previousUTXOs), a pure
// revocation — spending the advert's output with no new MessageBox
// output anywhere in the same transaction — must delete the engine's
// own storage row, not just the lookup index (the lookup index already
// dropped the advert pre-fix, since OutputSpent fires unconditionally;
// this test is specifically about the engine's bookkeeping, that bug
// found).
func TestMessageBoxEngine_PureRevocationDeletesStorageRow(t *testing.T) {
	ctx := context.Background()
	eng := newFixPassTestEngine(t)

	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	identityPub := priv.PubKey().Compressed()
	identityHex := hex.EncodeToString(identityPub)
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "messagebox advertisement"}
	party := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}
	pd := &pushdrop.PushDrop{Wallet: w}
	advertScript, err := pd.Lock(ctx, [][]byte{identityPub, []byte("https://h.example.org")}, proto, "1", party, true, true, pushdrop.LockBefore)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	advertTx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: advertScript, Satoshis: 1000})

	steak1 := submitMessageBoxTx(t, eng, advertTx)
	if inst, ok := steak1[topics.MessageBoxTopicName]; !ok || inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("expected advert admitted, got %+v", inst)
	}

	q, err := json.Marshal(topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	before, err := eng.Lookup(ctx, &lookup.LookupQuestion{Service: topics.MessageBoxLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup before revoke: %v", err)
	}
	if len(before.Outputs) != 1 {
		t.Fatalf("expected the advert resolvable before revocation, got %d outputs", len(before.Outputs))
	}

	// A pure revocation: spend the advert's output with no new
	// MessageBox-shaped output anywhere among this tx's outputs.
	rev := transaction.NewTransaction()
	if err := rev.AddInputFrom(advertTx.TxID().String(), 0, advertScript.String(), 1000, nil); err != nil {
		t.Fatalf("AddInputFrom: %v", err)
	}
	rev.Inputs[0].SourceTransaction = advertTx
	payout := script.Script{script.OpTRUE}
	rev.AddOutput(&transaction.TransactionOutput{LockingScript: &payout, Satoshis: 900})
	unlockingScript, err := pd.Unlock(ctx, proto, "1", party, wallet.SignOutputsAll, false).Sign(rev, 0)
	if err != nil {
		t.Fatalf("sign revoke input: %v", err)
	}
	rev.Inputs[0].UnlockingScript = unlockingScript

	steak2 := submitMessageBoxTx(t, eng, rev)
	revInst, ok := steak2[topics.MessageBoxTopicName]
	if !ok || revInst == nil || len(revInst.OutputsToAdmit) != 0 {
		t.Fatalf("expected the revocation to admit no new output, got %+v", revInst)
	}
	if len(revInst.CoinsToRetain) != 0 {
		t.Fatalf("expected a pure revocation to retain zero coins, got CoinsToRetain=%v (pre-fix bug: always retained every previous coin)", revInst.CoinsToRetain)
	}

	after, err := eng.Lookup(ctx, &lookup.LookupQuestion{Service: topics.MessageBoxLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup after revoke: %v", err)
	}
	if len(after.Outputs) != 0 {
		t.Fatalf("expected the lookup index to drop the revoked advert, got %d outputs", len(after.Outputs))
	}

	// The lookup index dropping the advert was already true pre-fix
	// (engine OutputSpent fires unconditionally). The coin-retention fix
	// changes the ENGINE'S OWN storage row: confirm it's gone, not
	// "spent=true but still stored" (the pre-fix symptom, and the
	// foothold a replay finding depends on). FindOutput reports a missing row as an error
	// here, not nil — either shape means "deleted."
	mbTopic := topics.MessageBoxTopicName
	stored, ferr := eng.Storage.FindOutput(ctx, &transaction.Outpoint{Txid: *advertTx.TxID(), Index: 0}, &mbTopic, nil, false)
	if ferr == nil && stored != nil {
		t.Fatalf("expected the advert's storage row deleted after a pure revocation, still stored: spent=%v consumedBy=%d", stored.Spent, len(stored.ConsumedBy))
	}
}

// submitMessageBoxTx wraps tx in a BEEF and submits it to tm_messagebox,
// failing the test on any Submit error. Mirrors uhrp_engine_test.go's
// submitUHRPTx.
func submitMessageBoxTx(t *testing.T, eng *engine.Engine, tx *transaction.Transaction) overlay.Steak {
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
		Topics: []string{topics.MessageBoxTopicName},
	}, engine.SubmitModeHistorical, nil)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return steak
}
