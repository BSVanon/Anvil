package main

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/headers"
	anvilmsg "github.com/BSVanon/Anvil/internal/messaging"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/BSVanon/Anvil/internal/overlay/v3engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// TestHomeRuleRealProductionEngine (below) exercises
// messageBoxAdvertSource's real production path (messaging_privacy.go)
// against a real v3engine.New + Submit pipeline, so
// MessageBoxTopicManager.Admit's signature verification is actually
// exercised end to end. wireMessagingPrivacy and wireGossipMessagingPolicy
// have their own, lighter tests in messaging_privacy_wire_test.go and
// messaging_privacy_gossip_wire_test.go, which register a
// MessageBoxLookupService directly rather than paying for a full engine
// round trip every time.

// TestHomeRuleRealProductionEngine is a permanent regression test for a bug
// a review once found here. Unlike
// wiringTestAdvert's lighter tests (which register a
// MessageBoxLookupService directly via engine.NewEngine and poke
// OutputAdmittedByTopic, with no signature check), this test goes
// through the SAME engine construction main.go uses in production
// (v3engine.New) and submits every advert/revocation through the real
// Submit pipeline, so MessageBoxTopicManager.Admit's signature
// verification is actually exercised end to end — exactly what the
// review found the existing tests never did. It walks all three
// HomeState answers: Home (an advert names this node's own
// public_url), Elsewhere (after revoking the Home advert, a second
// advert for the same identity naming a different host remains live),
// and Unadvertised (after revoking that one too).
func TestHomeRuleRealProductionEngine(t *testing.T) {
	root := t.TempDir()
	dir, err := anviloverlay.NewDirectory(filepath.Join(root, "overlay"))
	if err != nil {
		t.Fatalf("open overlay directory: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	hs, err := headers.NewTestStore(filepath.Join(root, "h"))
	if err != nil {
		t.Fatalf("open headers store: %v", err)
	}
	t.Cleanup(func() { _ = hs.Close() })
	overlaytest.SeedFundingBlock(t, hs)
	eng, err := v3engine.New(&v3engine.Config{
		Storage:      anvilstorage.New(dir.DB()),
		HeadersStore: hs,
		LookupDB:     dir.DB(),
		HostingURL:   "https://my-anvil.example.org",
	})
	if err != nil {
		t.Fatalf("v3engine.New: %v", err)
	}
	if svc, ok := eng.GetLookupService(topics.MessageBoxLookupServiceName); !ok {
		t.Fatalf("ls_messagebox not registered on the production engine: %T", svc)
	}

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
	pd := &pushdrop.PushDrop{Wallet: w}
	proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "messagebox advertisement"}
	party := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}

	lockAdvert := func(host string) *script.Script {
		s, err := pd.Lock(context.Background(), [][]byte{identityPub, []byte(host)}, proto, "1", party, true, true, pushdrop.LockBefore)
		if err != nil {
			t.Fatalf("PushDrop Lock: %v", err)
		}
		return s
	}
	submit := func(tx *transaction.Transaction) {
		t.Helper()
		beef, err := transaction.NewBeefFromTransaction(tx)
		if err != nil {
			t.Fatal(err)
		}
		b, err := beef.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Submit(context.Background(), overlay.TaggedBEEF{Beef: b, Topics: []string{topics.MessageBoxTopicName}}, engine.SubmitModeHistorical, nil); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	revoke := func(spent *transaction.Transaction, lockedScript *script.Script, satoshis, payout uint64) {
		t.Helper()
		rev := transaction.NewTransaction()
		if err := rev.AddInputFrom(spent.TxID().String(), 0, lockedScript.String(), satoshis, nil); err != nil {
			t.Fatal(err)
		}
		rev.Inputs[0].SourceTransaction = spent
		out := script.Script{script.OpTRUE}
		rev.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: payout})
		unlockScript, err := pd.Unlock(context.Background(), proto, "1", party, wallet.SignOutputsAll, false).Sign(rev, 0)
		if err != nil {
			t.Fatalf("Unlock.Sign: %v", err)
		}
		rev.Inputs[0].UnlockingScript = unlockScript
		submit(rev)
	}

	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"
	home := wireMessagingPrivacy(cfg, eng, dir).Home

	// Home: a canonical advert naming this node's own public_url, admitted
	// through the real pipeline (signature verified by Admit).
	homeScript := lockAdvert("https://my-anvil.example.org")
	homeTx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: homeScript, Satoshis: 1000})
	submit(homeTx)
	res, err := home.Resolve(identityHex)
	if err != nil {
		t.Fatalf("Resolve (home): %v", err)
	}
	if res.State != anvilmsg.Home {
		t.Fatalf("State = %v, want Home — the production wiring must find the real admitted advert", res.State)
	}

	// Elsewhere: a second live advert for the same identity naming a
	// different host. Revoke the Home advert first so the answer isn't
	// still Home (the Home rule counts ANY current qualifying advert).
	elsewhereScript := lockAdvert("https://some-other-node.example.org")
	elsewhereTx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: elsewhereScript, Satoshis: 999})
	submit(elsewhereTx)
	revoke(homeTx, homeScript, 1000, 900)

	res, err = home.Resolve(identityHex)
	if err != nil {
		t.Fatalf("Resolve (elsewhere): %v", err)
	}
	if res.State != anvilmsg.Elsewhere {
		t.Fatalf("State = %v, want Elsewhere after revoking the Home advert", res.State)
	}

	// Unadvertised: revoke the remaining (Elsewhere) advert too.
	revoke(elsewhereTx, elsewhereScript, 999, 899)
	res, err = home.Resolve(identityHex)
	if err != nil {
		t.Fatalf("Resolve (unadvertised): %v", err)
	}
	if res.State != anvilmsg.Unadvertised {
		t.Fatalf("State = %v, want Unadvertised after revoking every advert", res.State)
	}
}
