package federation

import (
	"context"
	"testing"

	oa "github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/ship"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/slap"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/utils"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// shipAdLock builds a SHIP advertisement locking script with the given
// counterparty/forSelf so lock↔unlock pairing can be exercised both ways.
func shipAdLock(t *testing.T, pd pushdrop.PushDrop, identity []byte, cp wallet.Counterparty, forSelf bool) *script.Script {
	t.Helper()
	protoID := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
		Protocol:      string(overlay.ProtocolSHIP.ID()),
	}
	lock, err := pd.Lock(context.Background(),
		[][]byte{[]byte(overlay.ProtocolSHIP), identity, []byte("https://anvil-a.test"), []byte("tm_uhrp")},
		protoID, "1", cp, forSelf, true, pushdrop.LockBefore)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	return lock
}

// unlockSatisfiesLock signs a spend of a SHIP ad output with the given unlock
// counterparty and runs the script interpreter to check the unlock satisfies
// the lock. This is the wallet-independent regression guard for revocation:
// it proves the revoke unlocker recipe matches the CreateAdvertisements lock
// recipe (and fails if they diverge), without needing a funded wallet.
func unlockSatisfiesLock(t *testing.T, pd pushdrop.PushDrop, lock *script.Script, unlockCP wallet.Counterparty) error {
	t.Helper()
	protoID := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
		Protocol:      string(overlay.ProtocolSHIP.ID()),
	}
	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{LockingScript: lock, Satoshis: 1})

	spendTx := transaction.NewTransaction()
	spendTx.AddInputFromTx(sourceTx, 0, nil)
	unlocker := pd.Unlock(context.Background(), protoID, "1", unlockCP, wallet.SignOutputsAll, false)
	us, err := unlocker.Sign(spendTx, 0)
	if err != nil {
		t.Fatalf("unlock sign: %v", err)
	}
	spendTx.Inputs[0].UnlockingScript = us
	return interpreter.NewEngine().Execute(
		interpreter.WithTx(spendTx, 0, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 1}),
		interpreter.WithForkID(),
		interpreter.WithAfterGenesis(),
	)
}

// TestRevoke_AnyoneUnlockRecipe_SatisfiesAnyoneLock is the revocation
// regression guard: the matching Anyone/forSelf unlock recipe must satisfy the
// Anyone/forSelf lock CreateAdvertisements now emits, and the old Self recipe
// must NOT — so revoke can't silently drift back to a recipe that can't spend
// the ad outputs.
func TestRevoke_AnyoneUnlockRecipe_SatisfiesAnyoneLock(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	pw, err := wallet.NewWallet(priv)
	if err != nil {
		t.Fatalf("wallet: %v", err)
	}
	pd := pushdrop.PushDrop{Wallet: &protoWalletAdapter{pw: pw}}
	anyone := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}

	lock := shipAdLock(t, pd, priv.PubKey().Compressed(), anyone, true)

	if err := unlockSatisfiesLock(t, pd, lock, anyone); err != nil {
		t.Fatalf("matching Anyone unlock must satisfy the Anyone lock, got: %v", err)
	}
	if err := unlockSatisfiesLock(t, pd, lock, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}); err == nil {
		t.Fatal("the old Self unlock recipe must NOT satisfy the Anyone lock, but it did")
	}
}

// protoWalletAdapter adapts a go-sdk ProtoWallet (*wallet.Wallet — key ops
// only) to the full wallet.Interface pushdrop.Lock requires, delegating just
// the two methods Lock uses (GetPublicKey + CreateSignature) so the real
// BRC-42 derivation/signing is exercised. Other methods are unused by Lock.
type protoWalletAdapter struct {
	wallet.Interface
	pw *wallet.Wallet
}

func (a *protoWalletAdapter) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, o string) (*wallet.GetPublicKeyResult, error) {
	return a.pw.GetPublicKey(ctx, args, o)
}

func (a *protoWalletAdapter) CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs, o string) (*wallet.CreateSignatureResult, error) {
	return a.pw.CreateSignature(ctx, args, o)
}

// buildShipTokenAndValidate builds a SHIP advertisement PushDrop using the
// given BRC-42 counterparty + forSelf flag (the two knobs that differ between
// go-sdk admin-token.Lock and the canonical WalletAdvertiser recipe), signs it
// with a fresh identity ProtoWallet, then runs it through the EXACT canonical
// admission signature-linkage gate (utils.IsTokenSignatureCorrectlyLinked,
// the check at go-overlay-discovery-services shared/admittance.go:88). Returns
// whether the token would be admitted.
func buildShipTokenAndValidate(t *testing.T, counterparty wallet.Counterparty, forSelf bool) bool {
	t.Helper()
	ctx := context.Background()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	pw, err := wallet.NewWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}

	protoID := wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
		Protocol:      string(overlay.ProtocolSHIP.ID()),
	}
	if protoID.Protocol == "" {
		t.Fatal("overlay.ProtocolSHIP.ID() is empty")
	}

	pd := pushdrop.PushDrop{Wallet: &protoWalletAdapter{pw: pw}}
	lock, err := pd.Lock(
		ctx,
		[][]byte{
			[]byte(overlay.ProtocolSHIP),
			priv.PubKey().Compressed(),
			[]byte("https://anvil-a.test"),
			[]byte("tm_uhrp"),
		},
		protoID,
		"1",
		counterparty,
		forSelf,
		true, // includeSignature
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("pushdrop Lock: %v", err)
	}

	decoded := pushdrop.Decode(lock)
	if decoded == nil {
		t.Fatal("pushdrop.Decode returned nil")
	}
	if len(decoded.Fields) != 5 {
		t.Fatalf("expected 5 fields (proto, identity, domain, topic, sig), got %d", len(decoded.Fields))
	}
	fields := make(utils.TokenFields, len(decoded.Fields))
	copy(fields, decoded.Fields)

	valid, err := utils.IsTokenSignatureCorrectlyLinked(ctx, decoded.LockingPublicKey.ToDERHex(), fields)
	if err != nil {
		t.Fatalf("IsTokenSignatureCorrectlyLinked error: %v", err)
	}
	return valid
}

// TestAdmission_AdminTokenRecipe_IsRejected documents the root cause of the
// SHIP/SLAP duplicate flood: go-sdk admin-token.Lock signs with
// counterparty=Self / forSelf=false, which the go-overlay-discovery-services
// admission validator REJECTS (it verifies via the anyone-wallet with
// counterparty=Other(identity), which only reciprocates the Anyone/forSelf
// recipe). Production node-a logs show exactly this: "Invalid token signature
// linkage" on every advertisement output, every cycle.
func TestAdmission_AdminTokenRecipe_IsRejected(t *testing.T) {
	valid := buildShipTokenAndValidate(t, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, false)
	if valid {
		t.Fatal("expected the Self/forSelf=false (admin-token.Lock) recipe to be REJECTED by canonical admission, but it passed")
	}
}

// TestAdmission_WalletAdvertiserRecipe_IsAdmitted proves the fix: the canonical
// WalletAdvertiser recipe — counterparty=Anyone / forSelf=true — produces a
// SHIP token the canonical admission gate ACCEPTS. Anvil's CreateAdvertisements
// must build SHIP/SLAP outputs this way instead of via go-sdk admin-token.Lock.
func TestAdmission_WalletAdvertiserRecipe_IsAdmitted(t *testing.T) {
	valid := buildShipTokenAndValidate(t, wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}, true)
	if !valid {
		t.Fatal("expected the Anyone/forSelf=true (WalletAdvertiser) recipe to be ADMITTED by canonical admission, but it was rejected")
	}
}

// e2eAdWallet is a wallet.Interface that performs real BRC-42 key ops (via a
// go-sdk ProtoWallet) AND funds CreateAction by wrapping the requested outputs
// in an input-less BEEF. It lets the end-to-end test exercise the actual
// Advertiser.CreateAdvertisements signing path and assert the produced tokens
// pass canonical admission — without a full go-wallet-toolbox + funding source.
type e2eAdWallet struct {
	wallet.Interface
	pw *wallet.Wallet
}

func (w *e2eAdWallet) GetPublicKey(ctx context.Context, args wallet.GetPublicKeyArgs, o string) (*wallet.GetPublicKeyResult, error) {
	return w.pw.GetPublicKey(ctx, args, o)
}

func (w *e2eAdWallet) CreateSignature(ctx context.Context, args wallet.CreateSignatureArgs, o string) (*wallet.CreateSignatureResult, error) {
	return w.pw.CreateSignature(ctx, args, o)
}

func (w *e2eAdWallet) CreateAction(_ context.Context, args wallet.CreateActionArgs, _ string) (*wallet.CreateActionResult, error) {
	tx := transaction.NewTransaction()
	for _, out := range args.Outputs {
		ls := script.Script(out.LockingScript)
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &ls, Satoshis: out.Satoshis})
	}
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		return nil, err
	}
	b, err := beef.Bytes()
	if err != nil {
		return nil, err
	}
	return &wallet.CreateActionResult{Tx: b}, nil
}

// TestAdvertiser_CreateAdvertisements_ProducesAdmittableTokens is the
// end-to-end regression Codex required: it drives the REAL
// Advertiser.CreateAdvertisements path and verifies every SHIP and SLAP output
// it emits passes the canonical admission signature-linkage gate. This is the
// guard against the duplicate-flood regression — before the fix these tokens
// were rejected ("Invalid token signature linkage") and never admitted.
func TestAdvertiser_CreateAdvertisements_ProducesAdmittableTokens(t *testing.T) {
	ctx := context.Background()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	pw, err := wallet.NewWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	a := &Advertiser{
		Wallet:     &e2eAdWallet{pw: pw},
		HostingURL: "https://anvil-a.test",
	}

	tagged, err := a.CreateAdvertisements([]*oa.AdvertisementData{
		{Protocol: overlay.ProtocolSHIP, TopicOrServiceName: "tm_uhrp"},
		{Protocol: overlay.ProtocolSLAP, TopicOrServiceName: "ls_uhrp"},
	})
	if err != nil {
		t.Fatalf("CreateAdvertisements: %v", err)
	}

	beef, tx, _, err := transaction.ParseBeef(tagged.Beef)
	if err != nil {
		t.Fatalf("parse tagged BEEF: %v", err)
	}
	if tx == nil || len(tx.Outputs) != 2 {
		t.Fatalf("expected 2 advertisement outputs, got %v", tx)
	}
	txid := tx.TxID()

	// Drive the FULL canonical admittance path (not just sub-gates): the
	// SHIP/SLAP topic managers' IdentifyAdmissibleOutputs enforces protocol
	// match, 5-field decode, advertisable URI, topic-name validity + prefix,
	// AND the signature-linkage check. Asserting the right output index is
	// admitted proves end-to-end admission — the real flood guard.
	db := newTestDB(t)
	shipTM := ship.NewTopicManager(NewSHIPStorage(db), ship.NewLookupService(NewSHIPStorage(db)))
	slapTM := slap.NewTopicManager(NewSLAPStorage(db), slap.NewLookupService(NewSLAPStorage(db)))

	shipAdmit, err := shipTM.IdentifyAdmissibleOutputs(ctx, beef, txid, nil)
	if err != nil {
		t.Fatalf("ship IdentifyAdmissibleOutputs: %v", err)
	}
	if !containsUint32(shipAdmit.OutputsToAdmit, 0) {
		t.Fatalf("SHIP ad output 0 NOT admitted by canonical tm_ship admittance: %v (flood regression)", shipAdmit.OutputsToAdmit)
	}

	slapAdmit, err := slapTM.IdentifyAdmissibleOutputs(ctx, beef, txid, nil)
	if err != nil {
		t.Fatalf("slap IdentifyAdmissibleOutputs: %v", err)
	}
	if !containsUint32(slapAdmit.OutputsToAdmit, 1) {
		t.Fatalf("SLAP ad output 1 NOT admitted by canonical tm_slap admittance: %v (flood regression)", slapAdmit.OutputsToAdmit)
	}
}

func containsUint32(haystack []uint32, needle uint32) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
