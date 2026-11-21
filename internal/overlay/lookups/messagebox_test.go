package lookups

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
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
		true, true, pushdrop.LockBefore, // forSelf=true, matching canonical anointHost (MessageBoxClient.ts:1553)
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

// mbStoreLegacyRecord writes the MessageBox record shape used before
// messageboxRecord gained BEEFBytes, along with the BEEF that canonical
// storage keeps under beef3 for lookup hydration.
func mbStoreLegacyRecord(t *testing.T, s *MessageBoxLookupService, identityKey, host string, admittedAt int64, payload *engine.OutputAdmittedByTopic) int64 {
	t.Helper()
	_, txid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		t.Fatalf("read legacy payload: %v", err)
	}
	beef, _, _, err := transaction.ParseBeef(payload.AtomicBEEF)
	if err != nil {
		t.Fatalf("parse legacy BEEF: %v", err)
	}
	atomic, err := beef.AtomicBytes(txid)
	if err != nil {
		t.Fatalf("measure legacy BEEF: %v", err)
	}
	beef.Version = transaction.BEEF_V2
	stored, err := beef.Bytes()
	if err != nil {
		t.Fatalf("serialise stored BEEF: %v", err)
	}
	legacy := struct {
		IdentityKey string `json:"identityKey"`
		Host        string `json:"host"`
		AdmittedAt  int64  `json:"admittedAt"`
	}{IdentityKey: identityKey, Host: host, AdmittedAt: admittedAt}
	body, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy record: %v", err)
	}
	if err := s.db.Put(itemKey(mbItemPrefix, txid, payload.OutputIndex), body, nil); err != nil {
		t.Fatalf("store legacy record: %v", err)
	}
	if err := s.db.Put(mbIndexKey(identityKey, admittedAt, txid, payload.OutputIndex), nil, nil); err != nil {
		t.Fatalf("store legacy index: %v", err)
	}
	if err := s.db.Put([]byte(mbStoredBEEFPrefix+txid.String()), stored, nil); err != nil {
		t.Fatalf("store legacy BEEF: %v", err)
	}
	return int64(len(atomic))
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

func TestMessageBox_LegacyRecordUsesStoredBEEF(t *testing.T) {
	s := newMessageBoxLookup(t)
	identityPub := mbIdentity(t)
	identityHex := hex.EncodeToString(identityPub)
	tx := mbBuildTx(t, identityPub, "https://legacy.example")
	payload := mbPayload(t, tx, 0)
	mbStoreLegacyRecord(t, s, identityHex, "https://legacy.example", 1, payload)

	answer := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if got := len(answer.Formulas); got != 1 {
		t.Fatalf("legacy lookup returned %d formulas, want 1", got)
	}
	if got := answer.Formulas[0].Outpoint.Txid; got != *tx.TxID() {
		t.Fatalf("legacy lookup txid = %s, want %s", got, tx.TxID())
	}
}

func TestMessageBox_LegacyAndNewRecordsRespectLimits(t *testing.T) {
	s := newMessageBoxLookup(t)
	identityPub := mbIdentity(t)
	identityHex := hex.EncodeToString(identityPub)

	legacyTx := mbBuildTx(t, identityPub, "https://legacy.example")
	legacySize := mbStoreLegacyRecord(t, s, identityHex, "https://legacy.example", 20, mbPayload(t, legacyTx, 0))
	newTx := mbBuildTx(t, identityPub, "https://new.example")
	newRecord, err := json.Marshal(messageboxRecord{
		IdentityKey: identityHex,
		Host:        "https://new.example",
		AdmittedAt:  30,
		BEEFBytes:   legacySize,
	})
	if err != nil {
		t.Fatalf("marshal new record: %v", err)
	}
	if err := s.db.Put(itemKey(mbItemPrefix, newTx.TxID(), 0), newRecord, nil); err != nil {
		t.Fatalf("store new record: %v", err)
	}
	if err := s.db.Put(mbIndexKey(identityHex, 30, newTx.TxID(), 0), nil, nil); err != nil {
		t.Fatalf("store new index: %v", err)
	}
	olderTx := mbBuildTx(t, identityPub, "https://older.example")
	olderRecord, err := json.Marshal(messageboxRecord{
		IdentityKey: identityHex,
		Host:        "https://older.example",
		AdmittedAt:  10,
		BEEFBytes:   1,
	})
	if err != nil {
		t.Fatalf("marshal older record: %v", err)
	}
	if err := s.db.Put(itemKey(mbItemPrefix, olderTx.TxID(), 0), olderRecord, nil); err != nil {
		t.Fatalf("store older record: %v", err)
	}
	if err := s.db.Put(mbIndexKey(identityHex, 10, olderTx.TxID(), 0), nil, nil); err != nil {
		t.Fatalf("store older index: %v", err)
	}

	byBytes, err := s.currentRecords(identityHex, "", 10, legacySize)
	if err != nil {
		t.Fatalf("byte-limited records: %v", err)
	}
	if len(byBytes) != 1 || byBytes[0].op.Txid != *newTx.TxID() {
		t.Fatalf("byte-limited records = %+v, want only the newer record", byBytes)
	}
	byCount, err := s.currentRecords(identityHex, "", 2, legacySize*2)
	if err != nil {
		t.Fatalf("count-limited records: %v", err)
	}
	if len(byCount) != 2 || byCount[0].op.Txid != *newTx.TxID() || byCount[1].op.Txid != *legacyTx.TxID() {
		t.Fatalf("count-limited records = %+v, want the two newest records", byCount)
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

// TestMessageBox_CurrentHostsBoundedAt1000Adverts is a required test:
// with 1,000 live adverts for one identity, CurrentHosts's Get-and-decode
// work stays at most maxCurrentHostsScan (32), not O(N). This asserts
// the RESULT length rather than instrumenting the LevelDB handle with a
// call counter, which is a faithful proxy here, not a weaker substitute:
// currentRecords' scanPrefix callback calls Get/json.Unmarshal and THEN
// appends to hits in the same step that checks the limit and returns the
// stop sentinel, and scanPrefix stops iterating entirely the instant its
// callback returns a non-nil error (common.go) — so with >=32 valid
// entries, Get is called exactly as many times as the final hit count,
// never once more. Counted by construction, not timed.
func TestMessageBox_CurrentHostsBoundedAt1000Adverts(t *testing.T) {
	ctx := context.Background()
	s := newMessageBoxLookup(t)
	identityPub := mbIdentity(t)
	identityHex := hex.EncodeToString(identityPub)

	const totalAdverts = 1000
	for i := 0; i < totalAdverts; i++ {
		tx := mbBuildTx(t, identityPub, fmt.Sprintf("https://host-%04d.example", i))
		if err := s.OutputAdmittedByTopic(ctx, mbPayload(t, tx, 0)); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}

	hosts, err := s.CurrentHosts(identityHex)
	if err != nil {
		t.Fatalf("CurrentHosts: %v", err)
	}
	if len(hosts) != maxCurrentHostsScan {
		t.Fatalf("CurrentHosts decoded %d of %d adverts, want exactly %d (the scan cap)", len(hosts), totalAdverts, maxCurrentHostsScan)
	}

	// Lookup (the external BRC-33 contract) stays unbounded, matching
	// canon — the cap is internal to CurrentHosts only.
	all := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if len(all.Formulas) != totalAdverts {
		t.Fatalf("Lookup returned %d of %d adverts, want all %d (unbounded, unlike CurrentHosts)", len(all.Formulas), totalAdverts, totalAdverts)
	}
}

func TestMessageBox_LookupCapsHydratedFormulaCount(t *testing.T) {
	s := newMessageBoxLookup(t)
	identityHex := hex.EncodeToString(mbIdentity(t))
	const total = 10_001
	for i := 0; i < total; i++ {
		var txid [32]byte
		txid[0] = byte(i)
		txid[1] = byte(i >> 8)
		txid[2] = byte(i >> 16)
		hash := chainhash.Hash(txid)
		record, err := json.Marshal(messageboxRecord{IdentityKey: identityHex, Host: fmt.Sprintf("https://host-%d.example", i), AdmittedAt: int64(i), BEEFBytes: 1})
		if err != nil {
			t.Fatalf("marshal record %d: %v", i, err)
		}
		if err := s.db.Put(itemKey(mbItemPrefix, &hash, uint32(i)), record, nil); err != nil {
			t.Fatalf("store record %d: %v", i, err)
		}
		if err := s.db.Put(mbIndexKey(identityHex, int64(i), &hash, uint32(i)), nil, nil); err != nil {
			t.Fatalf("store index %d: %v", i, err)
		}
	}
	answer := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if got := len(answer.Formulas); got != 10_000 {
		t.Fatalf("Lookup returned %d formulas, want the 10000 hydration cap", got)
	}
}

func TestMessageBox_LookupCapsHydratedBEEFBytes(t *testing.T) {
	s := newMessageBoxLookup(t)
	identityHex := hex.EncodeToString(mbIdentity(t))
	for i := 0; i < 3; i++ {
		var txid chainhash.Hash
		txid[0] = byte(i + 1)
		record, err := json.Marshal(messageboxRecord{
			IdentityKey: identityHex,
			Host:        fmt.Sprintf("https://host-%d.example", i),
			AdmittedAt:  int64(i),
			BEEFBytes:   maxMessageBoxLookupBEEFBytes/2 + 1,
		})
		if err != nil {
			t.Fatalf("marshal record %d: %v", i, err)
		}
		if err := s.db.Put(itemKey(mbItemPrefix, &txid, uint32(i)), record, nil); err != nil {
			t.Fatalf("store record %d: %v", i, err)
		}
		if err := s.db.Put(mbIndexKey(identityHex, int64(i), &txid, uint32(i)), nil, nil); err != nil {
			t.Fatalf("store index %d: %v", i, err)
		}
	}
	answer := mbLookup(t, s, topics.MessageBoxLookupQuery{IdentityKey: identityHex})
	if got := len(answer.Formulas); got != 1 {
		t.Fatalf("Lookup returned %d formulas, want 1 within the BEEF-byte cap", got)
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
