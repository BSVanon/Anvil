package main

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
	anvilmsg "github.com/BSVanon/Anvil/internal/messaging"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// These exercise wireMessagingPrivacy (messaging_privacy.go): does it find
// the real registered ls_messagebox service on a real engine, adapt it
// correctly, and pass the right pointers through. wiringTestAdvert
// registers a MessageBoxLookupService directly via engine.NewEngine and
// pokes OutputAdmittedByTopic without going through signature
// verification, so it is a lighter stand-in for a real admitted advert —
// see TestHomeRuleRealProductionEngine (messaging_privacy_test.go) for
// the full production-engine path.

// wiringTestAdvert builds a real *anviloverlay.Directory, a real
// lookups.MessageBoxLookupService registered under
// topics.MessageBoxLookupServiceName backed by the SAME LevelDB handle
// (mirroring main.go's own overlayDir.DB() reuse), with one admitted
// advert for identityPub at host already indexed — mirroring
// internal/overlay/lookups/messagebox_test.go's own admission helper
// (unexported there, so rebuilt here rather than reached across
// packages). It registers the service directly via engine.NewEngine and
// pokes OutputAdmittedByTopic without going through signature
// verification, so it is NOT a substitute for a real admitted advert —
// see TestHomeRuleRealProductionEngine below for that. It exists so
// the lighter tests in this file can exercise wireMessagingPrivacy's own
// adaptation logic (pointer threading, nil handling) without paying for
// a full v3engine.New + Submit round trip every time.
func wiringTestAdvert(t *testing.T, identityPub []byte, host string) (*engine.Engine, *anviloverlay.Directory) {
	t.Helper()
	dir, err := anviloverlay.NewDirectory(filepath.Join(t.TempDir(), "overlay"))
	if err != nil {
		t.Fatalf("open overlay directory: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	svc := lookups.NewMessageBoxLookupService(dir.DB())

	lockPriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	lockWallet, err := wallet.NewCompletedProtoWallet(lockPriv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	pd := &pushdrop.PushDrop{Wallet: lockWallet}
	lockingScript, err := pd.Lock(
		context.Background(),
		[][]byte{identityPub, []byte(host)},
		wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "messagebox advertisement"},
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		true, // forSelf, matching canonical anointHost (MessageBoxClient.ts:1553)
		true, // includeSignature
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}

	tx := transaction.NewTransaction()
	out := script.Script(lockingScript.Bytes())
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: 1})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	blob, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	if err := svc.OutputAdmittedByTopic(context.Background(), &engine.OutputAdmittedByTopic{
		Topic:       topics.MessageBoxTopicName,
		OutputIndex: 0,
		AtomicBEEF:  blob,
	}); err != nil {
		t.Fatalf("admit: %v", err)
	}

	eng := engine.NewEngine(&engine.Config{
		LookupServices: map[string]engine.LookupService{
			topics.MessageBoxLookupServiceName: svc,
		},
	})
	return eng, dir
}

// TestWireMessagingPrivacyHomeViaRealRegisteredLookupService proves the
// full real chain: config's [node] public_url -> ownHosts ->
// messaging.NewHomeResolver -> messageBoxAdvertSource -> a
// lookups.MessageBoxLookupService reader built against the shared
// overlay LevelDB handle -> CurrentHosts -> a real admitted advert in
// LevelDB -> Resolve answers Home.
func TestWireMessagingPrivacyHomeViaRealRegisteredLookupService(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	identityPub := priv.PubKey().Compressed()
	identityHex := hex.EncodeToString(identityPub)

	eng, dir := wiringTestAdvert(t, identityPub, "https://my-anvil.example.org")

	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"

	home := wireMessagingPrivacy(cfg, eng, dir).Home
	res, err := home.Resolve(identityHex)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != anvilmsg.Home {
		t.Fatalf("State = %v, want Home (public_url matches the advertised host)", res.State)
	}
}

// TestWireMessagingPrivacyElsewhereWhenAdvertDoesNotMatchOwnHosts proves
// the same chain answers Elsewhere when the advert names a host that is
// neither [node] public_url nor any [messaging] home_hosts entry.
func TestWireMessagingPrivacyElsewhereWhenAdvertDoesNotMatchOwnHosts(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	identityPub := priv.PubKey().Compressed()
	identityHex := hex.EncodeToString(identityPub)

	eng, dir := wiringTestAdvert(t, identityPub, "https://some-other-node.example.org")

	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"
	cfg.Messaging.HomeHosts = []string{"https://my-second-host.example.org"}

	home := wireMessagingPrivacy(cfg, eng, dir).Home
	res, err := home.Resolve(identityHex)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != anvilmsg.Elsewhere {
		t.Fatalf("State = %v, want Elsewhere (advert names neither public_url nor home_hosts)", res.State)
	}
}

// TestWireMessagingPrivacyNilEngineIsUnadvertised: overlay disabled
// (v3Eng == nil and overlayDir == nil, as cmd/anvil leaves them when
// cfg.Overlay.Enabled is false) must not panic and must answer
// Unadvertised for every recipient, per messageBoxAdvertSource's
// documented nil-AdvertSource fallback.
func TestWireMessagingPrivacyNilEngineIsUnadvertised(t *testing.T) {
	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"

	home := wireMessagingPrivacy(cfg, nil, nil).Home
	res, err := home.Resolve("anyone")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != anvilmsg.Unadvertised {
		t.Fatalf("State = %v, want Unadvertised (nil engine)", res.State)
	}
}

// TestWireMessagingPrivacyEngineWithoutMessageBoxServiceIsUnadvertised:
// an engine that hosts other topics but never registered
// tm_messagebox/ls_messagebox (e.g. a node that disabled that specific
// topic) must not panic and must answer Unadvertised — the
// GetLookupService ok==false branch.
func TestWireMessagingPrivacyEngineWithoutMessageBoxServiceIsUnadvertised(t *testing.T) {
	eng := engine.NewEngine(&engine.Config{})
	dir, err := anviloverlay.NewDirectory(filepath.Join(t.TempDir(), "overlay"))
	if err != nil {
		t.Fatalf("open overlay directory: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"

	home := wireMessagingPrivacy(cfg, eng, dir).Home
	res, err := home.Resolve("anyone")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != anvilmsg.Unadvertised {
		t.Fatalf("State = %v, want Unadvertised (no ls_messagebox registered)", res.State)
	}
}

// TestWireMessagingPrivacyPassesThroughConfigPointers confirms the two
// pointers returned are the SAME pointers config.Load's
// normalizeMessagingPrivacy already normalised — no accidental copy,
// re-derivation, or re-interpretation of the pointer-nil-vs-zero
// sentinel on the way through.
func TestWireMessagingPrivacyPassesThroughConfigPointers(t *testing.T) {
	ttl := int64(3600)
	allow := false
	cfg := &config.Config{}
	cfg.Messaging.ForwardCopyTTLSeconds = &ttl
	cfg.Messaging.OperatorReadsAllBoxes = &allow

	policy := wireMessagingPrivacy(cfg, nil, nil)
	gotTTL, gotAllow := policy.ForwardCopyTTLSeconds, policy.OperatorReadsAllBoxes
	if gotTTL != cfg.Messaging.ForwardCopyTTLSeconds {
		t.Fatalf("ForwardCopyTTLSeconds pointer not passed through verbatim")
	}
	if gotAllow != cfg.Messaging.OperatorReadsAllBoxes {
		t.Fatalf("OperatorReadsAllBoxes pointer not passed through verbatim")
	}
}
