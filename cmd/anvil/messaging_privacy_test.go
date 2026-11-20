package main

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/config"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	anvilmsg "github.com/BSVanon/Anvil/internal/messaging"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

// These exercise wireMessagingPrivacy / wireGossipMessagingPolicy /
// messageBoxAdvertSource (messaging_privacy.go) — the cmd/anvil glue
// that turns a loaded config and the already-constructed v3 engine into
// the HomeResolver + policy values internal/api and internal/gossip
// consume. The admission/lookup logic these lean on (ls_messagebox
// itself) is already covered exhaustively by
// internal/overlay/lookups/messagebox_test.go and
// internal/overlay/topics/messagebox_test.go; what's new and untested
// elsewhere is this file's own wiring: does it find the real registered
// service on a real engine, adapt it correctly, and pass the right
// pointers through to both consumers.

// wiringTestAdvert builds a real engine.Engine with a real
// lookups.MessageBoxLookupService registered under
// topics.MessageBoxLookupServiceName, backed by a temp LevelDB, with one
// admitted advert for identityPub at host already indexed — mirroring
// internal/overlay/lookups/messagebox_test.go's own admission helper
// (unexported there, so rebuilt here rather than reached across
// packages).
func wiringTestAdvert(t *testing.T, identityPub []byte, host string) *engine.Engine {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	svc := lookups.NewMessageBoxLookupService(db)

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
		false, true, pushdrop.LockBefore,
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

	return engine.NewEngine(&engine.Config{
		LookupServices: map[string]engine.LookupService{
			topics.MessageBoxLookupServiceName: svc,
		},
	})
}

// TestWireMessagingPrivacyHomeViaRealRegisteredLookupService proves the
// full real chain: config's [node] public_url -> ownHosts ->
// messaging.NewHomeResolver -> messageBoxAdvertSource ->
// engine.GetLookupService -> type-assert to
// *lookups.MessageBoxLookupService -> CurrentHosts -> a real admitted
// advert in LevelDB -> Resolve answers Home.
func TestWireMessagingPrivacyHomeViaRealRegisteredLookupService(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	identityPub := priv.PubKey().Compressed()
	identityHex := hex.EncodeToString(identityPub)

	eng := wiringTestAdvert(t, identityPub, "https://my-anvil.example.org")

	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"

	home, _, _ := wireMessagingPrivacy(cfg, eng)
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

	eng := wiringTestAdvert(t, identityPub, "https://some-other-node.example.org")

	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"
	cfg.Messaging.HomeHosts = []string{"https://my-second-host.example.org"}

	home, _, _ := wireMessagingPrivacy(cfg, eng)
	res, err := home.Resolve(identityHex)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != anvilmsg.Elsewhere {
		t.Fatalf("State = %v, want Elsewhere (advert names neither public_url nor home_hosts)", res.State)
	}
}

// TestWireMessagingPrivacyNilEngineIsUnadvertised: overlay disabled
// (v3Eng == nil, as cmd/anvil leaves it when cfg.Overlay.Enabled is
// false) must not panic and must answer Unadvertised for every
// recipient, per messageBoxAdvertSource's documented nil-AdvertSource
// fallback.
func TestWireMessagingPrivacyNilEngineIsUnadvertised(t *testing.T) {
	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"

	home, _, _ := wireMessagingPrivacy(cfg, nil)
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
	cfg := &config.Config{}
	cfg.Node.PublicURL = "https://my-anvil.example.org"

	home, _, _ := wireMessagingPrivacy(cfg, eng)
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

	_, gotTTL, gotAllow := wireMessagingPrivacy(cfg, nil)
	if gotTTL != cfg.Messaging.ForwardCopyTTLSeconds {
		t.Fatalf("ForwardCopyTTLSeconds pointer not passed through verbatim")
	}
	if gotAllow != cfg.Messaging.OperatorReadsAllBoxes {
		t.Fatalf("OperatorReadsAllBoxes pointer not passed through verbatim")
	}
}

// TestWireGossipMessagingPolicyNilManagerNoPanic: mesh disabled
// (gossipMgr == nil, as cmd/anvil leaves it when no mesh peers/listen
// are configured) must be a safe no-op.
func TestWireGossipMessagingPolicyNilManagerNoPanic(t *testing.T) {
	cfg := &config.Config{}
	wireGossipMessagingPolicy(nil, cfg, anvilmsg.AlwaysUnadvertised, nil)
}

// TestWireGossipMessagingPolicyAppliesToRealManager constructs a
// minimal real *gossip.Manager (same construction shape as
// internal/gossip's own allowlist_test.go helper) and confirms applying
// the policy through the wiring helper does not panic, for both an
// empty forward_peers list and a populated one — the two shapes
// NewForwardPeerFilter treats differently (nil filter vs. a real
// predicate). internal/gossip/handlers_msg_policy_test.go already
// covers the resulting forwarding behaviour in depth; this covers only
// that cmd/anvil's glue reaches SetMessagingPolicy correctly for both
// config shapes.
func TestWireGossipMessagingPolicyAppliesToRealManager(t *testing.T) {
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	mgr := anvilgossip.NewManager(anvilgossip.ManagerConfig{
		Wallet:  wallet.NewTestWallet(t, priv),
		MaxSeen: 100,
	})

	ttl := int64(3600)
	cfg := &config.Config{}
	wireGossipMessagingPolicy(mgr, cfg, anvilmsg.AlwaysUnadvertised, &ttl)

	cfg.Messaging.ForwardPeers = []string{"0231600bb272175e990e1639cba5c8f0a8e8c820c7c1b446d2301b0950957f9f66"}
	wireGossipMessagingPolicy(mgr, cfg, anvilmsg.AlwaysUnadvertised, &ttl)
}
