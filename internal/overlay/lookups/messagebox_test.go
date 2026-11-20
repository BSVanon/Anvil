package lookups

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/syndtr/goleveldb/leveldb"
)

func newMessageBoxLookup(t *testing.T) *MessageBoxLookupService {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open leveldb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewMessageBoxLookupService(db)
}

// mbLockFields signs an arbitrary field set with the canonical
// MessageBox advert protocol. The appended signature does not need to
// verify against the identity named in field[0] here — the lookup-side
// index path (ParseMessageBoxOutput) only decodes shape; admission
// verifies signatures. Mirrors kvstore_test.go's analogous comment.
func mbLockFields(t *testing.T, fields [][]byte) []byte {
	t.Helper()
	lockPriv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	lockWallet, err := wallet.NewCompletedProtoWallet(lockPriv)
	if err != nil {
		t.Fatalf("new wallet: %v", err)
	}
	pd := &pushdrop.PushDrop{Wallet: lockWallet}
	s, err := pd.Lock(
		context.Background(),
		fields,
		wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "messagebox advertisement"},
		"1",
		wallet.Counterparty{Type: wallet.CounterpartyTypeAnyone},
		false, true, pushdrop.LockBefore,
	)
	if err != nil {
		t.Fatalf("PushDrop Lock: %v", err)
	}
	return s.Bytes()
}

// mbBuildTx builds a tx carrying a single MessageBox PushDrop output
// advertising identityKeyHex at host.
func mbBuildTx(t *testing.T, identityPub []byte, host string) *transaction.Transaction {
	t.Helper()
	scriptBytes := mbLockFields(t, [][]byte{identityPub, []byte(host)})
	tx := transaction.NewTransaction()
	out := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &out, Satoshis: 1})
	return tx
}

// mbPayload wraps tx as an OutputAdmittedByTopic notify payload (Atomic
// BEEF), pointing at outputIndex.
func mbPayload(t *testing.T, tx *transaction.Transaction, outputIndex uint32) *engine.OutputAdmittedByTopic {
	t.Helper()
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	blob, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return &engine.OutputAdmittedByTopic{
		Topic:       topics.MessageBoxTopicName,
		OutputIndex: outputIndex,
		AtomicBEEF:  blob,
	}
}

func mbIdentity(t *testing.T) []byte {
	t.Helper()
	priv, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("new priv: %v", err)
	}
	return priv.PubKey().Compressed()
}

func mbLookup(t *testing.T, s *MessageBoxLookupService, q topics.MessageBoxLookupQuery) *lookup.LookupAnswer {
	t.Helper()
	body, _ := json.Marshal(q)
	ans, err := s.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.MessageBoxLookupServiceName,
		Query:   body,
	})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return ans
}

// TestMessageBox_AdmitAndFound pins the canonical port's full round
// trip from the spec's test list: "an advert built exactly the way
// anointHost builds it is admitted and found." Admission is covered in
// topics/messagebox_test.go; this covers "found" via ls_messagebox.
func TestMessageBox_AdmitAndFound(t *testing.T) {
	ctx := context.Background()
	s := newMessageBoxLookup(t)
	identityPub := mbIdentity(t)
	identityHex := hex.EncodeToString(identityPub)

	tx := mbBuildTx(t, identityPub, "https://messagebox.example")
	if err := s.OutputAdmittedByTopic(ctx, mbPayload(t, tx, 0)); err != nil {
		t.Fatalf("admit: %v", err)
	}

	ans := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if ans.Type != lookup.AnswerTypeFormula || len(ans.Formulas) != 1 {
		t.Fatalf("expected 1 formula, got type=%s n=%d", ans.Type, len(ans.Formulas))
	}
	wantTxid := tx.TxID()
	if ans.Formulas[0].Outpoint == nil || ans.Formulas[0].Outpoint.Txid != *wantTxid || ans.Formulas[0].Outpoint.Index != 0 {
		t.Fatalf("unexpected outpoint: %+v", ans.Formulas[0].Outpoint)
	}
}

// TestMessageBox_QueryByHostFilters confirms the optional host= selector
// narrows an identity's multiple adverts to an exact match.
func TestMessageBox_QueryByHostFilters(t *testing.T) {
	ctx := context.Background()
	s := newMessageBoxLookup(t)
	identityPub := mbIdentity(t)
	identityHex := hex.EncodeToString(identityPub)

	tx1 := mbBuildTx(t, identityPub, "https://a.example")
	tx2 := mbBuildTx(t, identityPub, "https://b.example")
	if err := s.OutputAdmittedByTopic(ctx, mbPayload(t, tx1, 0)); err != nil {
		t.Fatalf("admit tx1: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctx, mbPayload(t, tx2, 0)); err != nil {
		t.Fatalf("admit tx2: %v", err)
	}

	all := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if len(all.Formulas) != 2 {
		t.Fatalf("expected 2 adverts before filtering, got %d", len(all.Formulas))
	}

	filtered := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex, Host: "https://b.example"})
	if len(filtered.Formulas) != 1 {
		t.Fatalf("expected 1 advert for host filter, got %d", len(filtered.Formulas))
	}
	wantTxid := tx2.TxID()
	if filtered.Formulas[0].Outpoint.Txid != *wantTxid {
		t.Fatalf("host filter returned wrong outpoint: %+v", filtered.Formulas[0].Outpoint)
	}
}

// TestMessageBox_SpendRemovesAdvert confirms a spend (OutputSpent)
// deletes the record so it no longer answers lookups.
func TestMessageBox_SpendRemovesAdvert(t *testing.T) {
	ctx := context.Background()
	s := newMessageBoxLookup(t)
	identityPub := mbIdentity(t)
	identityHex := hex.EncodeToString(identityPub)

	tx := mbBuildTx(t, identityPub, "https://messagebox.example")
	if err := s.OutputAdmittedByTopic(ctx, mbPayload(t, tx, 0)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	ans := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if len(ans.Formulas) != 1 {
		t.Fatalf("expected 1 advert before spend, got %d", len(ans.Formulas))
	}

	outpoint := &transaction.Outpoint{Txid: *tx.TxID(), Index: 0}
	if err := s.OutputSpent(ctx, &engine.OutputSpent{Topic: topics.MessageBoxTopicName, Outpoint: outpoint}); err != nil {
		t.Fatalf("OutputSpent: %v", err)
	}

	ans = mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if len(ans.Formulas) != 0 {
		t.Fatalf("expected 0 adverts after spend, got %d", len(ans.Formulas))
	}
}

// TestMessageBox_IdentityKeyRequired confirms the canonical "identityKey
// query missing" error (MessageBoxLookupService.ts:59-61).
func TestMessageBox_IdentityKeyRequired(t *testing.T) {
	s := newMessageBoxLookup(t)
	_, err := s.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.MessageBoxLookupServiceName,
		Query:   []byte(`{}`),
	})
	if err == nil {
		t.Fatal("expected an error for a missing identityKey")
	}
}

// TestMessageBox_CurrentHosts exercises the native Go side-channel
// messaging.HomeResolver uses, confirming it returns the same live hosts
// Lookup would, without requiring a BEEF round trip from the caller.
func TestMessageBox_CurrentHosts(t *testing.T) {
	ctx := context.Background()
	s := newMessageBoxLookup(t)
	identityPub := mbIdentity(t)
	identityHex := hex.EncodeToString(identityPub)

	tx1 := mbBuildTx(t, identityPub, "https://a.example")
	tx2 := mbBuildTx(t, identityPub, "https://b.example")
	if err := s.OutputAdmittedByTopic(ctx, mbPayload(t, tx1, 0)); err != nil {
		t.Fatalf("admit tx1: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctx, mbPayload(t, tx2, 0)); err != nil {
		t.Fatalf("admit tx2: %v", err)
	}

	hosts, err := s.CurrentHosts(identityHex)
	if err != nil {
		t.Fatalf("CurrentHosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %+v", hosts)
	}
	found := map[string]bool{}
	for _, h := range hosts {
		found[h] = true
	}
	if !found["https://a.example"] || !found["https://b.example"] {
		t.Fatalf("missing expected hosts: %+v", hosts)
	}

	// An identity with no adverts at all returns an empty, non-error result.
	noneHex := hex.EncodeToString(mbIdentity(t))
	hosts, err = s.CurrentHosts(noneHex)
	if err != nil {
		t.Fatalf("CurrentHosts (none): %v", err)
	}
	if len(hosts) != 0 {
		t.Fatalf("expected 0 hosts for an unadvertised identity, got %+v", hosts)
	}
}
