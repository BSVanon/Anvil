package federation

import (
	"context"
	"errors"
	"testing"

	oa "github.com/bsv-blockchain/go-overlay-services/pkg/core/advertiser"
	"github.com/bsv-blockchain/go-overlay-discovery-services/pkg/types"
	"github.com/bsv-blockchain/go-sdk/overlay"
	admintoken "github.com/bsv-blockchain/go-sdk/overlay/admin-token"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// stubWallet is a minimal wallet.Interface stub for tests that only
// exercise the PushDrop Lock path. Returns a fixed identity key and
// signs deterministically using a fixed private key. Anything beyond
// GetPublicKey + CreateSignature is reported as unimplemented so tests
// don't accidentally lean on stub behavior.
type stubWallet struct {
	wallet.Interface
	priv *ec.PrivateKey
}

func newStubWallet(t *testing.T) *stubWallet {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	return &stubWallet{priv: priv}
}

func (s *stubWallet) GetPublicKey(_ context.Context, args wallet.GetPublicKeyArgs, _ string) (*wallet.GetPublicKeyResult, error) {
	if args.IdentityKey {
		return &wallet.GetPublicKeyResult{PublicKey: s.priv.PubKey()}, nil
	}
	return &wallet.GetPublicKeyResult{PublicKey: s.priv.PubKey()}, nil
}

func (s *stubWallet) CreateSignature(_ context.Context, args wallet.CreateSignatureArgs, _ string) (*wallet.CreateSignatureResult, error) {
	// Sign whatever's in Data (or HashToDirectlySign) — admin-token
	// builds the appropriate preimage; we just need a deterministic
	// signature so the PushDrop output is well-formed.
	var msg []byte
	switch {
	case len(args.HashToDirectlySign) > 0:
		msg = args.HashToDirectlySign
	default:
		msg = args.Data
	}
	sig, err := s.priv.Sign(msg)
	if err != nil {
		return nil, err
	}
	return &wallet.CreateSignatureResult{Signature: sig}, nil
}

func (s *stubWallet) CreateAction(_ context.Context, _ wallet.CreateActionArgs, _ string) (*wallet.CreateActionResult, error) {
	return nil, errors.New("stubWallet: CreateAction not implemented in test")
}

// TestAdvertiser_ParseAdvertisement_RoundtripsCanonicalAdminToken pins
// the canonical contract: a SHIP PushDrop output built via
// admin-token.OverlayAdminToken.Lock must roundtrip through our
// ParseAdvertisement and yield the same Protocol/Domain/TopicOrService.
// Without this, federation peers asking us to parse their ads (via the
// engine's parseAdvertisementDomain at engine.go:1085) would silently
// reject everything.
func TestAdvertiser_ParseAdvertisement_RoundtripsCanonicalAdminToken(t *testing.T) {
	w := newStubWallet(t)
	pd := admintoken.NewOverlayAdminToken(w)
	const (
		domain         = "https://anvil-a.test"
		topicOrService = "tm_uhrp"
	)
	lock, err := pd.Lock(context.Background(), overlay.ProtocolSHIP, domain, topicOrService)
	if err != nil {
		t.Fatalf("admin-token Lock: %v", err)
	}

	a := &Advertiser{HostingURL: domain}
	ad, err := a.ParseAdvertisement(lock)
	if err != nil {
		t.Fatalf("ParseAdvertisement: %v", err)
	}
	if ad == nil {
		t.Fatal("expected non-nil advertisement")
	}
	if ad.Protocol != overlay.ProtocolSHIP {
		t.Fatalf("Protocol mismatch: want SHIP, got %s", ad.Protocol)
	}
	if ad.Domain != domain {
		t.Fatalf("Domain mismatch: want %s, got %s", domain, ad.Domain)
	}
	if ad.TopicOrService != topicOrService {
		t.Fatalf("TopicOrService mismatch: want %s, got %s", topicOrService, ad.TopicOrService)
	}
	if ad.IdentityKey == "" {
		t.Fatal("IdentityKey must be populated from canonical admin-token decode")
	}
}

// TestAdvertiser_ParseAdvertisement_SLAPProtocol confirms ParseAdvertisement
// handles SLAP as well as SHIP (same canonical path, different protocol).
func TestAdvertiser_ParseAdvertisement_SLAPProtocol(t *testing.T) {
	w := newStubWallet(t)
	pd := admintoken.NewOverlayAdminToken(w)
	lock, err := pd.Lock(context.Background(), overlay.ProtocolSLAP, "https://anvil-b.test", "ls_uhrp")
	if err != nil {
		t.Fatalf("admin-token Lock: %v", err)
	}
	a := &Advertiser{}
	ad, err := a.ParseAdvertisement(lock)
	if err != nil {
		t.Fatalf("ParseAdvertisement: %v", err)
	}
	if ad.Protocol != overlay.ProtocolSLAP {
		t.Fatalf("Protocol mismatch: want SLAP, got %s", ad.Protocol)
	}
}

// TestAdvertiser_ParseAdvertisement_RejectsNonAdminScript confirms that
// a random script (not a PushDrop admin token) returns nil + error
// without panicking. Critical for safety when the engine's
// parseAdvertisementDomain fans out ParseAdvertisement across every
// output in a SHIP/SLAP lookup answer — some may not be admin tokens.
func TestAdvertiser_ParseAdvertisement_RejectsNonAdminScript(t *testing.T) {
	a := &Advertiser{}
	// Plain P2PKH-style script: not a PushDrop admin token.
	junk := script.NewFromBytes([]byte{0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac})
	ad, err := a.ParseAdvertisement(junk)
	if ad != nil {
		t.Fatalf("expected nil advertisement for non-admin script, got %+v", ad)
	}
	if err == nil {
		t.Fatal("expected error for non-admin script")
	}
}

// TestAdvertiser_ParseAdvertisement_RejectsEmpty confirms guard against
// nil and zero-length scripts.
func TestAdvertiser_ParseAdvertisement_RejectsEmpty(t *testing.T) {
	a := &Advertiser{}
	if _, err := a.ParseAdvertisement(nil); err == nil {
		t.Fatal("expected error for nil script")
	}
	empty := script.NewFromBytes([]byte{})
	if _, err := a.ParseAdvertisement(empty); err == nil {
		t.Fatal("expected error for empty script")
	}
}

// TestAdvertiser_FindAllAdvertisements_EmptyWhenNoHostingURL pins the
// canonical wire shape: when an operator runs without a public URL
// (single-node mode), FindAllAdvertisements returns an empty slice not
// nil, matching what the upstream JSON layer expects.
func TestAdvertiser_FindAllAdvertisements_EmptyWhenNoHostingURL(t *testing.T) {
	a := &Advertiser{HostingURL: ""}
	got, err := a.FindAllAdvertisements(overlay.ProtocolSHIP)
	if err != nil {
		t.Fatalf("FindAllAdvertisements: %v", err)
	}
	if got == nil {
		t.Fatal("expected empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %d entries", len(got))
	}
}

// TestAdvertiser_FindAllAdvertisements_NoStoreMatchesReturnsEmpty
// verifies that when the local SHIP/SLAP store has no entries matching
// our HostingURL, we return an empty slice without erroring. This is
// the typical state on a fresh node before its first SyncAdvertisements
// pass.
func TestAdvertiser_FindAllAdvertisements_NoStoreMatchesReturnsEmpty(t *testing.T) {
	db := newTestDB(t)
	a := &Advertiser{
		HostingURL: "https://anvil-x.test",
		SHIPStore:  NewSHIPStorage(db),
		SLAPStore:  NewSLAPStorage(db),
	}
	got, err := a.FindAllAdvertisements(overlay.ProtocolSHIP)
	if err != nil {
		t.Fatalf("FindAllAdvertisements SHIP: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no SHIP entries, got %d", len(got))
	}
	got, err = a.FindAllAdvertisements(overlay.ProtocolSLAP)
	if err != nil {
		t.Fatalf("FindAllAdvertisements SLAP: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no SLAP entries, got %d", len(got))
	}
}

// TestAdvertiser_FindAllAdvertisements_RejectsUnsupportedProtocol
// pins the validation that prevents the engine from accidentally
// requesting non-SHIP/SLAP advertisement protocols.
func TestAdvertiser_FindAllAdvertisements_RejectsUnsupportedProtocol(t *testing.T) {
	db := newTestDB(t)
	a := &Advertiser{
		HostingURL: "https://anvil-x.test",
		SHIPStore:  NewSHIPStorage(db),
		SLAPStore:  NewSLAPStorage(db),
	}
	if _, err := a.FindAllAdvertisements(overlay.Protocol("BOGUS")); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

// TestAdvertiser_CreateAdvertisements_RejectsInvalidInputs pins guards
// against nil receivers, empty ad lists, and unsupported protocols.
// These are the upstream-engine-driven error paths we expect to see in
// production logs if SyncAdvertisements wires up something unexpected.
func TestAdvertiser_CreateAdvertisements_RejectsInvalidInputs(t *testing.T) {
	a := &Advertiser{Wallet: newStubWallet(t), HostingURL: "https://anvil-x.test"}
	if _, err := a.CreateAdvertisements(nil); err == nil {
		t.Fatal("expected error for nil ad list")
	}
	if _, err := a.CreateAdvertisements([]*oa.AdvertisementData{}); err == nil {
		t.Fatal("expected error for empty ad list")
	}
	if _, err := a.CreateAdvertisements([]*oa.AdvertisementData{nil}); err == nil {
		t.Fatal("expected error for nil ad entry")
	}
	if _, err := a.CreateAdvertisements([]*oa.AdvertisementData{{Protocol: "BOGUS", TopicOrServiceName: "tm_x"}}); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}

	noWallet := &Advertiser{HostingURL: "https://anvil-x.test"}
	if _, err := noWallet.CreateAdvertisements([]*oa.AdvertisementData{{Protocol: overlay.ProtocolSHIP, TopicOrServiceName: "tm_uhrp"}}); err == nil {
		t.Fatal("expected error for nil wallet")
	}
}

// TestAdvertiser_BEEFEmptyFallback_PreservesTopicOrService pins
// Codex review 18af38d602483289 finding #1: when an output is in
// anvilstorage but its BEEF is nil (typical post-W-4-B migration
// state), the hydration fallback must use the local SHIP record to
// populate TopicOrService + IdentityKey. Without this, every
// SyncAdvertisements cycle would treat the existing ad as "missing"
// (engine.go:914-918 matches on Domain && TopicOrService) and emit a
// duplicate SHIP output to chain.
//
// Test stub: write a SHIP record directly into the local store, then
// invoke loadCanonicalRecord with the matching outpoint. Verify Topic +
// IdentityKey come back populated.
func TestAdvertiser_BEEFEmptyFallback_PreservesTopicOrService(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	shipStore := NewSHIPStorage(db)
	slapStore := NewSLAPStorage(db)
	const (
		hostingURL = "https://anvil-a.test"
		txid       = "deadbeef00000000000000000000000000000000000000000000000000000000"
		topic      = "tm_uhrp"
		idkey      = "02abcdef00"
	)
	if err := shipStore.StoreSHIPRecord(ctx, txid, 0, idkey, hostingURL, topic); err != nil {
		t.Fatalf("seed SHIP record: %v", err)
	}

	a := &Advertiser{
		HostingURL: hostingURL,
		SHIPStore:  shipStore,
		SLAPStore:  slapStore,
	}
	got, gotIK, err := a.loadCanonicalRecord(ctx, types.UTXOReference{Txid: txid, OutputIndex: 0}, overlay.ProtocolSHIP)
	if err != nil {
		t.Fatalf("loadCanonicalRecord: %v", err)
	}
	if got != topic {
		t.Fatalf("TopicOrService mismatch: want %s, got %q", topic, got)
	}
	if gotIK != idkey {
		t.Fatalf("IdentityKey mismatch: want %s, got %q", idkey, gotIK)
	}

	// SLAP path verification.
	if err := slapStore.StoreSLAPRecord(ctx, txid, 1, idkey, hostingURL, "ls_uhrp"); err != nil {
		t.Fatalf("seed SLAP record: %v", err)
	}
	gotSvc, _, err := a.loadCanonicalRecord(ctx, types.UTXOReference{Txid: txid, OutputIndex: 1}, overlay.ProtocolSLAP)
	if err != nil {
		t.Fatalf("loadCanonicalRecord SLAP: %v", err)
	}
	if gotSvc != "ls_uhrp" {
		t.Fatalf("SLAP service mismatch: want ls_uhrp, got %q", gotSvc)
	}
}

// TestAdvertiser_RevokeAdvertisements_PerTxStrategy verifies the
// per-advertisement CreateAction loop replaces the rejected
// concat-BEEF approach. Uses a stubWallet that records every
// CreateAction call so the test can assert one call per ad.
//
// Codex review 18af38d602483289 finding #2: go-sdk wallet decodes
// InputBEEF as one envelope, so concatenating multiple ad.Beef buffers
// produces malformed input. Per-tx revoke is the canonical-safe
// alternative.
func TestAdvertiser_RevokeAdvertisements_PerTxStrategy(t *testing.T) {
	w := &recordingWallet{stubWallet: newStubWallet(t)}
	a := &Advertiser{Wallet: w, HostingURL: "https://anvil-a.test"}

	// Two fake ads with different topics + non-empty BEEF blobs.
	ads := []*oa.Advertisement{
		{Protocol: overlay.ProtocolSHIP, TopicOrService: "tm_uhrp", Beef: validFakeBEEF(t), OutputIndex: 0},
		{Protocol: overlay.ProtocolSLAP, TopicOrService: "ls_uhrp", Beef: validFakeBEEF(t), OutputIndex: 0},
	}
	_, err := a.RevokeAdvertisements(ads)
	if err == nil {
		t.Fatalf("expected stub CreateAction to surface, got nil")
	}
	if w.calls != 1 {
		t.Fatalf("expected 1 CreateAction call before stub error, got %d (err=%v)", w.calls, err)
	}
	if len(w.lastInputBEEF) != len(ads[0].Beef) {
		t.Fatalf("InputBEEF must equal single ad's BEEF (per-tx strategy), got len %d vs %d",
			len(w.lastInputBEEF), len(ads[0].Beef))
	}
}

// recordingWallet wraps stubWallet to capture CreateAction args. Used
// by the per-tx revoke strategy test to verify InputBEEF is the
// individual ad's BEEF, not a concatenated buffer.
type recordingWallet struct {
	*stubWallet
	calls         int
	lastInputBEEF []byte
}

var errCreateActionStub = errors.New("recordingWallet: stub")

func (r *recordingWallet) CreateAction(_ context.Context, args wallet.CreateActionArgs, _ string) (*wallet.CreateActionResult, error) {
	r.calls++
	r.lastInputBEEF = args.InputBEEF
	return nil, errCreateActionStub
}

// validFakeBEEF returns a real-but-minimal BEEF buffer for tests.
// The per-tx revoke test calls txidFromBEEF(ad.Beef) before CreateAction,
// so the BEEF must actually parse — a hand-rolled byte string fails the
// envelope check. We build a real Transaction + wrap it in BEEF via
// the canonical go-sdk helpers.
func validFakeBEEF(t *testing.T) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	// Single 0-sat output with a trivial locking script. The wallet
	// would refuse to broadcast this, but the per-tx test only needs
	// txidFromBEEF + the InputBEEF length comparison to succeed.
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: script.NewFromBytes([]byte{0x51}), // OP_1 — minimal valid script
	})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("validFakeBEEF: build BEEF: %v", err)
	}
	body, err := beef.Bytes()
	if err != nil {
		t.Fatalf("validFakeBEEF: encode BEEF: %v", err)
	}
	return body
}

// TestEncodeBEEF_AcceptsWalletBEEF guards the v3.0.0 → v3.0.1 fix.
// wallet.CreateAction returns res.Tx in BEEF format (V1/V2/AtomicBEEF),
// not raw tx bytes. The original v3.0.0 implementation called
// NewTransactionFromBytes on this, which mis-decoded a BEEF magic
// header as a tx version+input count and a downstream length varint
// as ~941 KB ("script(941643): got 6695 bytes: unexpected EOF" in
// production logs on Anvil Prime, 2026-05-25). This test feeds a
// real BEEF in and asserts encodeBEEF re-emits a parseable BEEF.
func TestEncodeBEEF_AcceptsWalletBEEF(t *testing.T) {
	walletBEEF := validFakeBEEF(t)

	out, err := encodeBEEF(walletBEEF)
	if err != nil {
		t.Fatalf("encodeBEEF on wallet BEEF: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("encodeBEEF returned empty bytes")
	}
	// The re-emitted BEEF must round-trip through canonical ParseBeef so
	// the engine.Submit pipeline accepts it.
	parsed, _, txid, err := transaction.ParseBeef(out)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("re-parse returned nil Beef")
	}
	if txid == nil {
		t.Fatal("re-parse returned nil txid")
	}
}

// TestEncodeBEEF_RejectsRawTxBytes documents the inverse: feeding raw
// tx bytes (not BEEF) is now an error rather than silent corruption.
// Anchors the assumption that wallet-toolbox always returns BEEF.
func TestEncodeBEEF_RejectsRawTxBytes(t *testing.T) {
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: script.NewFromBytes([]byte{0x51}),
	})
	if _, err := encodeBEEF(tx.Bytes()); err == nil {
		t.Fatal("expected error feeding raw tx bytes (not BEEF) to encodeBEEF")
	}
}

// TestAdvertiser_RevokeAdvertisements_RejectsInvalidInputs mirrors
// CreateAdvertisements guards plus the missing-BEEF path.
func TestAdvertiser_RevokeAdvertisements_RejectsInvalidInputs(t *testing.T) {
	a := &Advertiser{Wallet: newStubWallet(t), HostingURL: "https://anvil-x.test"}
	if _, err := a.RevokeAdvertisements(nil); err == nil {
		t.Fatal("expected error for nil ad list")
	}
	if _, err := a.RevokeAdvertisements([]*oa.Advertisement{}); err == nil {
		t.Fatal("expected error for empty ad list")
	}
	if _, err := a.RevokeAdvertisements([]*oa.Advertisement{nil}); err == nil {
		t.Fatal("expected error for nil ad entry")
	}
	if _, err := a.RevokeAdvertisements([]*oa.Advertisement{{Protocol: overlay.ProtocolSHIP, Domain: "x"}}); err == nil {
		t.Fatal("expected error for missing BEEF")
	}
}
