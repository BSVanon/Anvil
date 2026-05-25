package lookups

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// fixtureBSV21TVZNScriptHex is a real mainnet BSV-21 OrdLock listing
// covenant (TVZN). Frozen byte-for-byte from
// internal/overlay/topics/ordlock_test.go where it was vendored from
// Anvil-Swap repo `src/ordlock/__fixtures__/bsv21-tvzn.json`. If the
// vendored covenant or parser drifts, both this fixture AND the topic
// test stop parsing — that's a coupled failure mode by design.
const fixtureBSV21TVZNScriptHex = "0063036f726451126170706c69636174696f6e2f6273762d3230004c767b2270223a226273762d3230222c226f70223a227472616e73666572222c22616d74223a223132303030222c226964223a22313765626432666337396262363737316431303264346333303138623562643263643930386663626232396137333239323732386433646662653562383862315f30227d682097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c0000145e4b9e78ae774eaeadcf05bd06a0ffbe4272fd1122000e2707000000001976a91428672b084a32711ee267c1e61f49771784620e9f88ac615179547a75537a537a537a0079537a75527a527a7575615579008763567901c161517957795779210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081059795679615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a75517a756169587951797e58797eaa577961007982775179517958947f7551790128947f77517a75517a75618777777777777777777767557951876351795779a9876957795779ac777777777777777767006868"

// Note: the parser keys partly off "_<vout>" inside the inscription `id`
// field — the TVZN fixture has id "..._0" so it's classified as BSV-21.
const fixtureBSV21TVZNTokenId = "17ebd2fc79bb6771d102d4c3018b5bd2cd908fcbb29a73292728d3dfbe5b88b1_0"

// Wait — actually parsing the TVZN fixture gives the values vendored in
// the topic test. The asserts below match those.
const fixtureBSV21TVZNCancelPkhHex = "5e4b9e78ae774eaeadcf05bd06a0ffbe4272fd11"

// fixtureBSV21TVZNCancelAddress is the base58check mainnet P2PKH derived
// from fixtureBSV21TVZNCancelPkhHex. We compute it inline below rather
// than hard-coding the base58 string — that's brittle if the address
// helper changes.
func fixtureBSV21TVZNCancelAddress(t *testing.T) string {
	t.Helper()
	// 0x00 (mainnet) + 20-byte pkh + 4-byte SHA256d checksum, encoded
	// base58. Easier: round-trip via NormalizeCancelFilter's inverse —
	// but we don't have one. So decode the helper's expected output.
	return mainnetP2PKHFromPkh(t, fixtureBSV21TVZNCancelPkhHex)
}

// liveVaultScriptHex is the OrdLockBuy fixture from topics/ordlock_buy_test.go.
const liveVaultScriptHex = "76009c63755279ab547a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad6908e803000000000000041976a9147e7b0288ac7e7e4cb30100000000000000aa0063036f726451126170706c69636174696f6e2f6273762d3230004c737b2270223a226273762d3230222c226f70223a227472616e73666572222c22616d74223a223530222c226964223a22336335646536313362333661616461643531646163333461303437326138373861343263343132356234343835303438313039323761333737643531363263345f30227d6876a9148dd8631a9c2285f523da15a1b8d874a3fda00eea88ac7c7e7c7eaa7c820128947f7701207f758767519d5279ab557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad69537a210312e3db769544cf899b8c0961594f6c474f1f4166ad0c1b47c55413e9f2321c54ad7c041976a9147e147d8cf389745e933753d26b970cb29437c4605a950288ac7e7e7c7eaa7c820128947f7701207f758768"

// buildAdmitPayloadForScript wraps a single-output tx (output 0 = the
// given locking script) in atomic BEEF and produces an
// OutputAdmittedByTopic targeting OutputIndex=0.
func buildAdmitPayloadForScript(t *testing.T, topic string, scriptBytes []byte) *engine.OutputAdmittedByTopic {
	t.Helper()
	tx := transaction.NewTransaction()
	s := script.Script(scriptBytes)
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &s, Satoshis: 1})
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	atomic, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatalf("AtomicBytes: %v", err)
	}
	return &engine.OutputAdmittedByTopic{
		Topic:       topic,
		OutputIndex: 0,
		AtomicBEEF:  atomic,
	}
}

func mainnetP2PKHFromPkh(t *testing.T, pkhHex string) string {
	t.Helper()
	// Use script.NewAddressFromPublicKeyHash (mainnet=true).
	pkh, err := hex.DecodeString(pkhHex)
	if err != nil {
		t.Fatalf("decode pkh: %v", err)
	}
	addr, err := script.NewAddressFromPublicKeyHash(pkh, true)
	if err != nil {
		t.Fatalf("new address: %v", err)
	}
	return addr.AddressString
}

// --- OrdLock listings tests ------------------------------------------------

func TestOrdLock_AdmitRealFixture(t *testing.T) {
	s := NewOrdLockLookupService(newLookupDB(t))
	scriptBytes, err := hex.DecodeString(fixtureBSV21TVZNScriptHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	p := buildAdmitPayloadForScript(t, topics.OrdLockTopicName, scriptBytes)
	if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
		t.Fatalf("admit: %v", err)
	}

	// Lookup by tokenId should return one formula.
	q, _ := json.Marshal(topics.OrdLockQuery{TokenId: fixtureBSV21TVZNTokenId})
	answer, err := s.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.OrdLockLookupServiceName,
		Query:   q,
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 match for tokenId, got %d", len(answer.Formulas))
	}

	// Lookup by cancelAddress should also find it.
	cancelAddr := fixtureBSV21TVZNCancelAddress(t)
	q2, _ := json.Marshal(topics.OrdLockQuery{CancelAddress: cancelAddr})
	answer2, err := s.Lookup(context.Background(), &lookup.LookupQuestion{
		Service: topics.OrdLockLookupServiceName,
		Query:   q2,
	})
	if err != nil {
		t.Fatalf("lookup cancelAddress: %v", err)
	}
	if len(answer2.Formulas) != 1 {
		t.Fatalf("expected 1 match for cancelAddress, got %d", len(answer2.Formulas))
	}
}

func TestOrdLock_SpendRemovesEntry(t *testing.T) {
	s := NewOrdLockLookupService(newLookupDB(t))
	scriptBytes, _ := hex.DecodeString(fixtureBSV21TVZNScriptHex)
	p := buildAdmitPayloadForScript(t, topics.OrdLockTopicName, scriptBytes)
	if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := outpointFromAdmitPayload(t, p)
	if err := s.OutputSpent(context.Background(), &engine.OutputSpent{Outpoint: op, Topic: topics.OrdLockTopicName}); err != nil {
		t.Fatalf("spend: %v", err)
	}
	q, _ := json.Marshal(topics.OrdLockQuery{TokenId: fixtureBSV21TVZNTokenId})
	answer, _ := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.OrdLockLookupServiceName, Query: q})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 after spend, got %d", len(answer.Formulas))
	}
}

func TestOrdLock_CancelAddressInvalidErrors(t *testing.T) {
	s := NewOrdLockLookupService(newLookupDB(t))
	q, _ := json.Marshal(topics.OrdLockQuery{CancelAddress: "not-a-valid-address"})
	_, err := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.OrdLockLookupServiceName, Query: q})
	if err == nil {
		t.Fatalf("expected error for invalid cancelAddress")
	}
}

func TestOrdLock_PaginationAndSort(t *testing.T) {
	s := NewOrdLockLookupService(newLookupDB(t))
	// We only have one fixture, so we admit the same one repeatedly with
	// different OutputIndex slots so they get distinct local keys. The
	// AdmittedAt clock has 1-second granularity so newest-first ordering
	// across rapid admits is non-deterministic — verify only the count
	// and the pagination clamping.
	scriptBytes, _ := hex.DecodeString(fixtureBSV21TVZNScriptHex)
	for i := 0; i < 3; i++ {
		p := buildAdmitPayloadForScript(t, topics.OrdLockTopicName, scriptBytes)
		// Tweak the tx by adding an extra dummy output so each iteration
		// gets a distinct txid → distinct local key.
		tx := transaction.NewTransaction()
		ls := script.Script(scriptBytes)
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &ls, Satoshis: 1})
		paddingScript := script.Script([]byte{0x00, 0x6a, byte(i)})
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &paddingScript, Satoshis: 0})
		beef, _ := transaction.NewBeefFromTransaction(tx)
		atomic, _ := beef.AtomicBytes(tx.TxID())
		p.AtomicBEEF = atomic
		p.OutputIndex = 0
		if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	q, _ := json.Marshal(topics.OrdLockQuery{TokenId: fixtureBSV21TVZNTokenId, Limit: 2})
	answer, err := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.OrdLockLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("paginated lookup: %v", err)
	}
	if len(answer.Formulas) != 2 {
		t.Fatalf("expected 2 (limit), got %d", len(answer.Formulas))
	}
}

// --- OrdLockBuy tests ------------------------------------------------------

func TestOrdLockBuy_AdmitRealFixture(t *testing.T) {
	s := NewOrdLockBuyLookupService(newLookupDB(t))
	scriptBytes, err := hex.DecodeString(liveVaultScriptHex)
	if err != nil {
		t.Fatalf("decode vault fixture: %v", err)
	}
	p := buildAdmitPayloadForScript(t, topics.OrdLockBuyTopicName, scriptBytes)
	if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
		t.Fatalf("admit: %v", err)
	}
	q, _ := json.Marshal(topics.OrdLockBuyQuery{Limit: 100})
	answer, err := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.OrdLockBuyLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 match, got %d", len(answer.Formulas))
	}
}

func TestOrdLockBuy_SpendRemovesEntry(t *testing.T) {
	s := NewOrdLockBuyLookupService(newLookupDB(t))
	scriptBytes, _ := hex.DecodeString(liveVaultScriptHex)
	p := buildAdmitPayloadForScript(t, topics.OrdLockBuyTopicName, scriptBytes)
	if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := outpointFromAdmitPayload(t, p)
	if err := s.OutputSpent(context.Background(), &engine.OutputSpent{Outpoint: op, Topic: topics.OrdLockBuyTopicName}); err != nil {
		t.Fatalf("spend: %v", err)
	}
	q, _ := json.Marshal(topics.OrdLockBuyQuery{Limit: 100})
	answer, _ := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.OrdLockBuyLookupServiceName, Query: q})
	if len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 after spend, got %d", len(answer.Formulas))
	}
}

func TestOrdLockBuy_OutpointFilter(t *testing.T) {
	s := NewOrdLockBuyLookupService(newLookupDB(t))
	scriptBytes, _ := hex.DecodeString(liveVaultScriptHex)
	p := buildAdmitPayloadForScript(t, topics.OrdLockBuyTopicName, scriptBytes)
	if err := s.OutputAdmittedByTopic(context.Background(), p); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := outpointFromAdmitPayload(t, p)
	q, _ := json.Marshal(topics.OrdLockBuyQuery{Outpoint: op.Txid.String() + "_0"})
	answer, err := s.Lookup(context.Background(), &lookup.LookupQuestion{Service: topics.OrdLockBuyLookupServiceName, Query: q})
	if err != nil {
		t.Fatalf("outpoint filter: %v", err)
	}
	if len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 for outpoint filter, got %d", len(answer.Formulas))
	}
}

// --- compile-time assertions ------------------------------------------------

func TestAllPhaseBLookups_ImplementInterface(t *testing.T) {
	var _ engine.LookupService = (*DEXSwapLookupService)(nil)
	var _ engine.LookupService = (*OrdLockLookupService)(nil)
	var _ engine.LookupService = (*OrdLockBuyLookupService)(nil)
}
