package lookups

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/storage"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// --- BRC-26 fixture helpers --------------------------------------------

// brc26FixtureProtocol is a throwaway signing protocol for these lookup
// fixtures. The lookup's read-side re-derivation (topics.ParseUHRPOutput /
// decodeUHRPBRC26) only re-checks SHAPE from an already-admitted output —
// it never re-verifies the signature (Admit did that once, at admission
// time) — so unlike the topics package's own BRC-26 tests, the protocol,
// keyID, and wallet used to sign a fixture here are arbitrary and need not
// match the real canonical uhrp-advertisement protocol/keyID.
var brc26FixtureProtocol = wallet.Protocol{
	SecurityLevel: wallet.SecurityLevelEveryApp,
	Protocol:      "uhrp lookup test fixture",
}

// freshUHRPHash returns a 32-byte content hash distinct per seed byte.
func freshUHRPHash(seed byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed
	}
	return h
}

// freshIdentityPub returns a fresh compressed (33-byte) public key, the
// shape a BRC-26 advertisement's identityKey field carries.
func freshIdentityPub(t *testing.T) []byte {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	return priv.PubKey().Compressed()
}

// buildUHRPBRC26AdmitPayload constructs an OutputAdmittedByTopic carrying a
// real atomic BEEF wrapping a canonical-shaped BRC-26 PushDrop
// advertisement: [identityPub, hash, url, varint expiry, varint size] plus
// an appended (throwaway-signed) signature field.
func buildUHRPBRC26AdmitPayload(t *testing.T, identityPub, hashBytes []byte, url string, expiry, size uint64) *engine.OutputAdmittedByTopic {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	w, err := wallet.NewCompletedProtoWallet(priv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	fields := [][]byte{
		identityPub,
		hashBytes,
		[]byte(url),
		util.VarInt(expiry).Bytes(),
		util.VarInt(size).Bytes(),
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	s, err := pd.Lock(
		context.Background(),
		fields,
		brc26FixtureProtocol,
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		false, // forSelf
		true,  // includeSignature
		pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}

	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: s, Satoshis: 1})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	txid := tx.TxID()
	atomicBytes, err := beef.AtomicBytes(txid)
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return &engine.OutputAdmittedByTopic{
		Topic:       topics.UHRPTopicName,
		OutputIndex: 0,
		AtomicBEEF:  atomicBytes,
	}
}

// withFixedNow overrides the package's nowUnix clock hook for the duration
// of a test, restoring it on cleanup.
func withFixedNow(t *testing.T, fixed int64) {
	t.Helper()
	orig := nowUnix
	nowUnix = func() int64 { return fixed }
	t.Cleanup(func() { nowUnix = orig })
}

// --- tests ---------------------------------------------------------------

// TestUHRPBRC26Lookup_LegacyHiddenWhenDuplicateExists confirms the
// Anvil-only dedup rule: a legacy advert resolves normally on its own, but
// once a BRC-26 advert exists for the SAME (content hash, URL) pair, the
// legacy entry is hidden from query results — though its underlying record
// is left in the index untouched (filtered at query time, not deleted).
func TestUHRPBRC26Lookup_LegacyHiddenWhenDuplicateExists(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0x20)
	hashHex := hex.EncodeToString(hash)
	url := "https://dup.example.com/same"

	legacyPayload := buildUHRPAdmitPayload(t, hashHex, url, "text/plain")
	if err := s.OutputAdmittedByTopic(ctxBg(), legacyPayload); err != nil {
		t.Fatalf("admit legacy: %v", err)
	}

	q, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: hashHex})
	answerBefore, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup before: %v", err)
	}
	if len(answerBefore.Formulas) != 1 {
		t.Fatalf("expected the legacy entry alone before any BRC-26 duplicate, got %d", len(answerBefore.Formulas))
	}

	brc26Payload := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), hash, url, 2000000000, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), brc26Payload); err != nil {
		t.Fatalf("admit brc26: %v", err)
	}

	answerAfter, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup after: %v", err)
	}
	if len(answerAfter.Formulas) != 1 {
		t.Fatalf("expected exactly 1 surviving entry (legacy now hidden), got %d", len(answerAfter.Formulas))
	}
	want := mustOutpointFromPayload(t, brc26Payload)
	if got := answerAfter.Formulas[0].Outpoint; got == nil || !got.Equal(want) {
		t.Fatalf("expected the BRC-26 outpoint to survive, got %v want %v", got, want)
	}

	recs, err := s.itemsByHash(strings.ToLower(hashHex))
	if err != nil {
		t.Fatalf("itemsByHash: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected both records still indexed (legacy + brc26), got %d", len(recs))
	}
}

// TestUHRPBRC26Lookup_ExpiredAdvertsSkipped confirms a BRC-26 advert whose
// absolute Unix-seconds expiry has passed (relative to the injected clock)
// is skipped from both a by-hash query and list=all, while a live advert
// in the same index is returned normally.
func TestUHRPBRC26Lookup_ExpiredAdvertsSkipped(t *testing.T) {
	s := newUHRPLookup(t)
	withFixedNow(t, 1000)

	expiredHash := freshUHRPHash(0x21)
	expiredPayload := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), expiredHash, "https://expired.example.com", 500, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), expiredPayload); err != nil {
		t.Fatalf("admit expired: %v", err)
	}

	livePayload := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), freshUHRPHash(0x22), "https://live.example.com", 2000, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), livePayload); err != nil {
		t.Fatalf("admit live: %v", err)
	}

	qAll, _ := json.Marshal(topics.UHRPLookupQuery{List: "all"})
	answer, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: qAll})
	if err != nil {
		t.Fatalf("lookup list=all: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 surviving (non-expired) formula, got %d", len(answer.Formulas))
	}
	want := mustOutpointFromPayload(t, livePayload)
	if got := answer.Formulas[0].Outpoint; got == nil || !got.Equal(want) {
		t.Fatalf("expected the live advert's outpoint, got %v want %v", got, want)
	}

	qExpired, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: hex.EncodeToString(expiredHash)})
	answerExpired, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: qExpired})
	if err != nil {
		t.Fatalf("lookup expired by hash: %v", err)
	}
	if len(answerExpired.Formulas) != 0 {
		t.Fatalf("expected 0 formulas for an expired advert's own hash query, got %d", len(answerExpired.Formulas))
	}
}

// TestUHRPBRC26Lookup_OutputSpentRemovesEntry confirms the lifecycle event
// spec item 2 requires: spending a canonical BRC-26 advertisement's UTXO
// removes it from the lookup index. Unlike the legacy OP_RETURN format
// (unspendable), a real spend is an expected part of a BRC-26 advert's
// life (revocation), so this is the more meaningful of the two formats to
// exercise end-to-end here.
func TestUHRPBRC26Lookup_OutputSpentRemovesEntry(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0x30)
	payload := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), hash, "https://spend.example.com", 2000000000, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	if err := s.OutputSpent(ctxBg(), &engine.OutputSpent{Outpoint: op, Topic: topics.UHRPTopicName}); err != nil {
		t.Fatalf("spend: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{ContentHash: hex.EncodeToString(hash)})
	answer, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 formulas after spend, got %d", len(answer.Formulas))
	}
}

// TestUHRPBRC26Lookup_ByUhrpUrl confirms a canonical uhrp:// URL (the shape
// a real @bsv/sdk StorageDownloader client sends — see
// TestUHRP_LookupByUhrpUrl for the legacy-format version of this same
// contract) resolves a BRC-26-sourced record too.
func TestUHRPBRC26Lookup_ByUhrpUrl(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0x40)
	payload := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), hash, "https://url.example.com/a", 2000000000, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	want := mustOutpointFromPayload(t, payload)

	b58, err := storage.GetURLForHash(hash)
	if err != nil {
		t.Fatalf("GetURLForHash: %v", err)
	}
	q, _ := json.Marshal(topics.UHRPLookupQuery{UhrpUrl: "uhrp://" + b58})
	answer, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula, got %d", len(answer.Formulas))
	}
	if got := answer.Formulas[0].Outpoint; got == nil || !got.Equal(want) {
		t.Fatalf("outpoint mismatch: got %v want %v", got, want)
	}
}
