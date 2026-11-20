package main

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/config"
	"github.com/BSVanon/Anvil/internal/envelope"
	anvilgossip "github.com/BSVanon/Anvil/internal/gossip"
	"github.com/BSVanon/Anvil/internal/headers"
	anvilmsg "github.com/BSVanon/Anvil/internal/messaging"
	anviloverlay "github.com/BSVanon/Anvil/internal/overlay"
	"github.com/BSVanon/Anvil/internal/overlay/lookups"
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
// see TestReviewR1ProductionEngineHomeRule below for that. It exists so
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

// TestReviewR1ProductionEngineHomeRule is the review's R1 reproduction
// (blocker B1), turned into a permanent regression test. Unlike
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
func TestReviewR1ProductionEngineHomeRule(t *testing.T) {
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
	home, _, _ := wireMessagingPrivacy(cfg, eng, dir)

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
	// still Home (decision 2 counts ANY current qualifying advert).
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

	home, _, _ := wireMessagingPrivacy(cfg, eng, dir)
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

	home, _, _ := wireMessagingPrivacy(cfg, eng, dir)
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

	home, _, _ := wireMessagingPrivacy(cfg, nil, nil)
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

	home, _, _ := wireMessagingPrivacy(cfg, eng, dir)
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

	_, gotTTL, gotAllow := wireMessagingPrivacy(cfg, nil, nil)
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

// TestDefaultsAcceptanceConfigLoadCatchesB2 is F4: the review's required
// "Defaults acceptance test" — config.Load's real defaults, then
// wireMessagingPrivacy and wireGossipMessagingPolicy, into a real
// gossip.Manager, with a real v3engine.New advert behind the
// HomeResolver (the same production construction
// TestReviewR1ProductionEngineHomeRule uses).
//
// The review's point (F4): every existing B2 regression test
// (internal/gossip/handlers_msg_policy_test.go's
// TestDeliverForward*DuplicateAlreadyStoredNotRelayedAgain) builds
// MessagingPolicy BY HAND with ForwardCopyTTLSeconds already non-nil —
// so they prove the fix works once wired, but nothing proves cmd/anvil's
// own wiring actually reaches that non-nil default from a real node
// startup. An empty [messaging] table has config.Load's own
// normalizeMessagingPrivacy (internal/config/messaging_privacy.go)
// default ForwardCopyTTLSeconds to 86400 — not nil — which is exactly
// what routes deliverForward into deliverHomeForward/deliverNonHomeForward
// (the fixed, ok-gated functions) rather than deliverLegacyForward
// (handlers_msg_policy.go:137-151, the pre-decision-3 fallback, which
// happens to relay correctly today but is a DIFFERENT code path and was
// never the one B2 broke). This test fails before B2's fix and would
// also fail if the wiring ever stopped reaching the fixed path.
//
// onMsgForward is unexported, so the only way to drive a real incoming
// forward from outside package gossip is a real mesh connection
// (mirroring internal/gossip's own newForwardPeerTestHub): a hub
// (production-wired, as above) with two connected peers — forwarder,
// which forwards a message the hub already has stored under the same
// MessageID (so Deliver returns ok=false, B2's exact bug shape), and
// observer, which must receive nothing if the hub's relay is correctly
// gated on ok. The recipient's advert names the hub's own public_url
// (Home) plus a second host (hasOtherHost=true), so a pre-fix hub would
// relay (hasOtherHost alone) while a fixed hub must not (ok is false).
func TestDefaultsAcceptanceConfigLoadCatchesB2(t *testing.T) {
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

	// config.Load, for real — a minimal TOML with an empty [messaging]
	// table, exactly like a fresh node's config, so ForwardCopyTTLSeconds
	// comes from normalizeMessagingPrivacy's own default, not a test
	// fixture's explicit value.
	cfgPath := filepath.Join(root, "anvil.toml")
	if err := os.WriteFile(cfgPath, []byte("[node]\nname = \"defaults-acceptance\"\npublic_url = \"https://my-anvil.example.org\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Messaging.ForwardCopyTTLSeconds == nil || *cfg.Messaging.ForwardCopyTTLSeconds != 86400 {
		t.Fatalf("expected config.Load to default forward_copy_ttl to 86400, got %v", cfg.Messaging.ForwardCopyTTLSeconds)
	}

	home, forwardCopyTTL, _ := wireMessagingPrivacy(cfg, eng, dir)

	hubKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	hubMsgStore, err := anvilmsg.NewStore(t.TempDir(), anvilmsg.Options{})
	if err != nil {
		t.Fatalf("messaging.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = hubMsgStore.Close() })
	hub := anvilgossip.NewManager(anvilgossip.ManagerConfig{
		Wallet:         wallet.NewTestWallet(t, hubKey),
		Store:          mustEnvelopeStore(t),
		LocalInterests: []string{""},
		MaxSeen:        100,
		IdentityKey:    hubKey,
	})
	t.Cleanup(func() { hub.Stop() })
	hub.SetMsgStore(hubMsgStore)
	wireGossipMessagingPolicy(hub, cfg, home, forwardCopyTTL)
	ts := httptest.NewServer(hub.MeshHandler())
	t.Cleanup(ts.Close)
	wsURL := "ws" + ts.URL[len("http"):]

	// A real admitted advert naming the hub's own public_url (Home) plus
	// a second host (hasOtherHost=true), through the real Submit
	// pipeline — same shape as TestReviewR1ProductionEngineHomeRule.
	recipientPriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	recipientPub := recipientPriv.PubKey().Compressed()
	recipientHex := hex.EncodeToString(recipientPub)
	advertWallet, err := wallet.NewCompletedProtoWallet(recipientPriv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	pd := &pushdrop.PushDrop{Wallet: advertWallet}
	proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "messagebox advertisement"}
	party := wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone}
	lockAdvert := func(host string) *script.Script {
		s, err := pd.Lock(context.Background(), [][]byte{recipientPub, []byte(host)}, proto, "1", party, true, true, pushdrop.LockBefore)
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
	homeTx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lockAdvert("https://my-anvil.example.org"), Satoshis: 1000})
	submit(homeTx)
	elsewhereTx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: lockAdvert("https://some-other-node.example.org"), Satoshis: 999})
	submit(elsewhereTx)

	res, err := home.Resolve(recipientHex)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != anvilmsg.Home || !res.HasOtherHost {
		t.Fatalf("Resolve = %+v, want Home with HasOtherHost=true", res)
	}

	// Pre-store the exact message the forward below carries, directly
	// against the hub's own store — simulating "this node already has
	// it" (an echo, a post-restart resend, or a msgSeen eviction retry),
	// so the incoming forward's own Deliver call returns ok=false.
	senderPriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	senderHex := hex.EncodeToString(senderPriv.PubKey().Compressed())
	msg := &anvilmsg.Message{
		Sender:     senderHex,
		Recipient:  recipientHex,
		MessageBox: "dex.swap",
		Body:       "offer-already-here",
		MessageID:  "defaults-acceptance-b2",
		Timestamp:  1700000000,
	}
	if ok, err := hubMsgStore.Deliver(msg, "pre-stored"); err != nil || !ok {
		t.Fatalf("pre-store on hub: ok=%v err=%v", ok, err)
	}

	forwarderKey, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	forwarder := anvilgossip.NewManager(anvilgossip.ManagerConfig{
		Wallet:         wallet.NewTestWallet(t, forwarderKey),
		Store:          mustEnvelopeStore(t),
		LocalInterests: []string{""},
		MaxSeen:        100,
		IdentityKey:    forwarderKey,
	})
	t.Cleanup(func() { forwarder.Stop() })
	if err := forwarder.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("forwarder ConnectPeer: %v", err)
	}

	observerMsgStore, err := anvilmsg.NewStore(t.TempDir(), anvilmsg.Options{})
	if err != nil {
		t.Fatalf("messaging.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = observerMsgStore.Close() })
	observer := anvilgossip.NewManager(anvilgossip.ManagerConfig{
		Wallet:         wallet.NewTestWalletForRandomKey(t),
		Store:          mustEnvelopeStore(t),
		LocalInterests: []string{""},
		MaxSeen:        100,
	})
	observer.SetMsgStore(observerMsgStore)
	t.Cleanup(func() { observer.Stop() })
	if err := observer.ConnectPeer(t.Context(), wsURL); err != nil {
		t.Fatalf("observer ConnectPeer: %v", err)
	}

	time.Sleep(600 * time.Millisecond)
	if hub.PeerCount() != 2 {
		t.Fatalf("expected 2 peers on hub, got %d", hub.PeerCount())
	}

	forwarder.ForwardMessage(msg)
	time.Sleep(600 * time.Millisecond)

	if observerMsgStore.Count() != 0 {
		t.Fatalf("observer store count = %d, want 0: a duplicate (already-stored) Home forward with hasOtherHost=true must not be relayed (B2), even through the config.Load-wired production path", observerMsgStore.Count())
	}
}

// mustEnvelopeStore builds a throwaway envelope.Store for a test gossip
// peer that only needs one to satisfy ManagerConfig — the messaging
// tests in this file don't exercise envelope delivery itself.
func mustEnvelopeStore(t *testing.T) *envelope.Store {
	t.Helper()
	s, err := envelope.NewStore(t.TempDir(), 3600, 65536)
	if err != nil {
		t.Fatalf("envelope.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
