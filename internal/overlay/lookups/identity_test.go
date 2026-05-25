package lookups

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

func newIdentityLookup(t *testing.T) *IdentityLookupService {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewIdentityLookupService(db)
}

// identityPlaceholder32 returns a base64-encoded 32-byte buffer for
// Type / SerialNumber fields. Wallet type system enforces the
// 32-byte ceiling.
func identityPlaceholder32(seed byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// buildIdentityAdmitPayload constructs an OutputAdmittedByTopic with a
// real atomic BEEF wrapping a tx whose output #0 is a PushDrop output
// embedding a signed identity Certificate (subject + certifier). The
// Identity admit path will cert.Verify() this and admit if valid.
func buildIdentityAdmitPayload(t *testing.T, subject, certifier *ec.PrivateKey, typeSeed, serialSeed byte) *engine.OutputAdmittedByTopic {
	t.Helper()
	certifierWallet, err := wallet.NewCompletedProtoWallet(certifier)
	if err != nil {
		t.Fatalf("certifier wallet: %v", err)
	}
	revHash, _ := chainhash.NewHashFromHex("0000000000000000000000000000000000000000000000000000000000000000")
	cert := &certificates.Certificate{
		Type:               wallet.StringBase64(identityPlaceholder32(typeSeed)),
		SerialNumber:       wallet.StringBase64(identityPlaceholder32(serialSeed)),
		Subject:            *subject.PubKey(),
		Certifier:          *certifier.PubKey(),
		RevocationOutpoint: &transaction.Outpoint{Txid: *revHash, Index: 0},
		Fields:             map[wallet.CertificateFieldNameUnder50Bytes]wallet.StringBase64{},
	}
	if err := cert.Sign(context.Background(), certifierWallet); err != nil {
		t.Fatalf("cert.Sign: %v", err)
	}
	certJSON, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}

	// Build a PushDrop script wrapping the JSON cert at field[0].
	lockPriv, _ := ec.NewPrivateKey()
	lockWallet, _ := wallet.NewCompletedProtoWallet(lockPriv)
	pd := &pushdrop.PushDrop{Wallet: lockWallet}
	s, err := pd.Lock(
		context.Background(),
		[][]byte{certJSON, {0x00}},
		wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "identity"},
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		false, false, pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}

	tx := transaction.NewTransaction()
	sb := s.Bytes()
	out := script.Script(sb)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: 1})

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
		Topic:       topics.IdentityTopicName,
		OutputIndex: 0,
		AtomicBEEF:  atomicBytes,
	}
}

func outpointFromIdentityPayload(t *testing.T, p *engine.OutputAdmittedByTopic) *transaction.Outpoint {
	t.Helper()
	_, txid, err := transaction.NewBeefFromAtomicBytes(p.AtomicBEEF)
	if err != nil {
		t.Fatalf("decode atomic beef: %v", err)
	}
	return &transaction.Outpoint{Txid: *txid, Index: p.OutputIndex}
}

// TestIdentity_AdmitAndLookupByIdentityKey pins the SendBSV-Wallet
// happy path: a signed identity cert is admitted, then a lookup by
// identityKey (hex of subject compressed pubkey) returns the outpoint.
// This is acceptance criterion #6 from SENDBSV_USERS_TOPIC_REQUEST.md.
func TestIdentity_AdmitAndLookupByIdentityKey(t *testing.T) {
	ctx := context.Background()
	s := newIdentityLookup(t)
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	payload := buildIdentityAdmitPayload(t, subject, certifier, 0x10, 0x20)

	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit: %v", err)
	}

	idKey := hex.EncodeToString(subject.PubKey().Compressed())
	q, _ := json.Marshal(topics.IdentityLookupQuery{IdentityKey: idKey})
	answer, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("Lookup by identityKey: %v", err)
	}
	if answer.Type != lookup.AnswerTypeFormula {
		t.Fatalf("expected formula answer, got %s", answer.Type)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula, got %d", len(answer.Formulas))
	}
	expected := outpointFromIdentityPayload(t, payload)
	if !answer.Formulas[0].Outpoint.Txid.IsEqual(&expected.Txid) {
		t.Fatalf("outpoint txid mismatch: want %s, got %s",
			expected.Txid.String(), answer.Formulas[0].Outpoint.Txid.String())
	}
}

// TestIdentity_LookupByCertifierKey pins the canonical filter pattern
// of scoping queries to a trusted certifier. Useful when consumers
// have a whitelist of trusted issuers.
func TestIdentity_LookupByCertifierKey(t *testing.T) {
	ctx := context.Background()
	s := newIdentityLookup(t)
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	payload := buildIdentityAdmitPayload(t, subject, certifier, 0x11, 0x21)
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit: %v", err)
	}

	certKey := hex.EncodeToString(certifier.PubKey().Compressed())
	q, _ := json.Marshal(topics.IdentityLookupQuery{CertifierKey: certKey})
	answer, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("Lookup by certifierKey: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula by certifierKey, got %d", len(answer.Formulas))
	}
}

// TestIdentity_LookupByIdentityAndCertifierFilters confirms the
// combined identityKey + certifierKey filter — same subject but
// scoped to a specific issuer.
func TestIdentity_LookupByIdentityAndCertifierFilters(t *testing.T) {
	ctx := context.Background()
	s := newIdentityLookup(t)
	subject, _ := ec.NewPrivateKey()
	cert1, _ := ec.NewPrivateKey()
	cert2, _ := ec.NewPrivateKey()

	if err := s.OutputAdmittedByTopic(ctx, buildIdentityAdmitPayload(t, subject, cert1, 0x12, 0x22)); err != nil {
		t.Fatalf("admit cert1: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctx, buildIdentityAdmitPayload(t, subject, cert2, 0x13, 0x23)); err != nil {
		t.Fatalf("admit cert2: %v", err)
	}

	// Lookup by identityKey alone should return both.
	idKey := hex.EncodeToString(subject.PubKey().Compressed())
	q, _ := json.Marshal(topics.IdentityLookupQuery{IdentityKey: idKey})
	answer, _ := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if len(answer.Formulas) != 2 {
		t.Fatalf("expected 2 formulas for subject with two issuers, got %d", len(answer.Formulas))
	}

	// Combined filter should return only the cert1-issued entry.
	certKey1 := hex.EncodeToString(cert1.PubKey().Compressed())
	q, _ = json.Marshal(topics.IdentityLookupQuery{IdentityKey: idKey, CertifierKey: certKey1})
	answer, _ = s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula with identityKey+certifierKey filter, got %d", len(answer.Formulas))
	}
}

// TestIdentity_AttributesQueryReturnsDeferred pins the W-11 deferral
// contract: an attributes-based query must NOT silently return empty
// — it returns a Freeform answer with a deferred flag so callers know
// to use the supported identityKey path instead.
func TestIdentity_AttributesQueryReturnsDeferred(t *testing.T) {
	ctx := context.Background()
	s := newIdentityLookup(t)
	q, _ := json.Marshal(topics.IdentityLookupQuery{
		Attributes: map[string]string{"handle": "alice", "domain": "sendbsv.com"},
	})
	answer, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("attributes query returned error (expected deferred answer): %v", err)
	}
	if answer.Type != lookup.AnswerTypeFreeform {
		t.Fatalf("expected freeform answer for attributes deferral, got %s", answer.Type)
	}
	body, _ := json.Marshal(answer.Result)
	var probe struct {
		Deferred bool   `json:"deferred"`
		Use      string `json:"use"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("decode deferred result: %v", err)
	}
	if !probe.Deferred {
		t.Fatal("expected deferred=true flag in attributes-query result")
	}
	if probe.Use != "identityKey" {
		t.Fatalf("expected 'use': identityKey hint, got %q", probe.Use)
	}
}

// TestIdentity_OutputSpent_RemovesEntry pins that rotating an identity
// cert (spend old, admit new) drops the old entry. Required for paymail
// resolvers to stop returning stale cert pointers.
func TestIdentity_OutputSpent_RemovesEntry(t *testing.T) {
	ctx := context.Background()
	s := newIdentityLookup(t)
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	payload := buildIdentityAdmitPayload(t, subject, certifier, 0x14, 0x24)
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := outpointFromIdentityPayload(t, payload)

	if err := s.OutputSpent(ctx, &engine.OutputSpent{
		Topic:    topics.IdentityTopicName,
		Outpoint: op,
	}); err != nil {
		t.Fatalf("OutputSpent: %v", err)
	}

	idKey := hex.EncodeToString(subject.PubKey().Compressed())
	q, _ := json.Marshal(topics.IdentityLookupQuery{IdentityKey: idKey})
	answer, _ := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected empty result after spend, got %d formulas", len(answer.Formulas))
	}
}

// TestIdentity_LookupRequiresSelector pins the validation that at
// least one of identityKey/certifierKey/outpoint/attributes must be
// present.
func TestIdentity_LookupRequiresSelector(t *testing.T) {
	ctx := context.Background()
	s := newIdentityLookup(t)
	q, _ := json.Marshal(topics.IdentityLookupQuery{})
	_, err := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if err == nil {
		t.Fatal("empty Identity query must surface a clear error")
	}
}

// TestIdentity_NonIdentityTopicIgnored confirms the engine fans every
// admit to every service; non-Identity topics must be silently
// skipped (matches IdentityLookupService.ts admission-mode filter).
func TestIdentity_NonIdentityTopicIgnored(t *testing.T) {
	ctx := context.Background()
	s := newIdentityLookup(t)
	subject, _ := ec.NewPrivateKey()
	certifier, _ := ec.NewPrivateKey()
	payload := buildIdentityAdmitPayload(t, subject, certifier, 0x15, 0x25)
	payload.Topic = "tm_uhrp"
	if err := s.OutputAdmittedByTopic(ctx, payload); err != nil {
		t.Fatalf("admit non-Identity: %v", err)
	}
	idKey := hex.EncodeToString(subject.PubKey().Compressed())
	q, _ := json.Marshal(topics.IdentityLookupQuery{IdentityKey: idKey})
	answer, _ := s.Lookup(ctx, &lookup.LookupQuestion{
		Service: topics.IdentityLookupServiceName,
		Query:   q,
	})
	if len(answer.Formulas) != 0 {
		t.Fatal("non-Identity admit should not have populated the index")
	}
}
