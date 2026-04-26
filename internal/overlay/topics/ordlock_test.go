package topics

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Real mainnet BSV-21 OrdLock fixture (TVZN) from Anvil-Swap repo
// `src/ordlock/__fixtures__/bsv21-tvzn.json`. Vendored here as a hex string
// so the test is self-contained and CI doesn't require the sibling repo.
const fixtureBSV21TVZNScriptHex = "0063036f726451126170706c69636174696f6e2f6273762d3230004c767b2270223a226273762d3230222c226f70223a227472616e73666572222c22616d74223a223132303030222c226964223a22313765626432666337396262363737316431303264346333303138623562643263643930386663626232396137333239323732386433646662653562383862315f30227d682097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c0000145e4b9e78ae774eaeadcf05bd06a0ffbe4272fd1122000e2707000000001976a91428672b084a32711ee267c1e61f49771784620e9f88ac615179547a75537a537a537a0079537a75527a527a7575615579008763567901c161517957795779210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081059795679615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e81517a75615779567956795679567961537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a75517a756169587951797e58797eaa577961007982775179517958947f7551790128947f77517a75517a75618777777777777777777767557951876351795779a9876957795779ac777777777777777767006868"

// Expected parse outputs for the TVZN fixture (sourced from the JSON sidecar
// at Anvil-Swap repo `src/ordlock/__fixtures__/bsv21-tvzn.json`).
const (
	fixtureBSV21TVZNTokenId      = "17ebd2fc79bb6771d102d4c3018b5bd2cd908fcbb29a73292728d3dfbe5b88b1_0"
	fixtureBSV21TVZNAmount       = "12000"
	fixtureBSV21TVZNPriceSats    = int64(120000000)
	fixtureBSV21TVZNCancelPkh    = "5e4b9e78ae774eaeadcf05bd06a0ffbe4272fd11"
	fixtureBSV21TVZNPayoutPkhHex = "28672b084a32711ee267c1e61f49771784620e9f"
)

// scriptFromHex builds a *script.Script from hex; fatal-on-error in tests.
func scriptFromHex(t *testing.T, h string) *script.Script {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	s := script.Script(b)
	return &s
}

// buildOrdLockScriptForTest assembles a canonical OrdLock script using the
// vendored prefix/suffix bytes. Mirrors the canonical TS builder closely
// enough to exercise the parser end-to-end without re-importing it.
func buildOrdLockScriptForTest(t *testing.T, inscription map[string]string, cancelPkh, payPkh []byte, priceSats uint64) *script.Script {
	t.Helper()
	if len(cancelPkh) != 20 || len(payPkh) != 20 {
		t.Fatalf("test pkh must be 20 bytes; got cancel=%d pay=%d", len(cancelPkh), len(payPkh))
	}

	jsonBytes, err := json.Marshal(inscription)
	if err != nil {
		t.Fatalf("marshal inscription: %v", err)
	}

	// payOutput = 8 sats LE + varint scriptLen (0x19 = 25) + P2PKH(payPkh).
	payOutput := make([]byte, 0, 8+1+25)
	for i := 0; i < 8; i++ {
		payOutput = append(payOutput, byte((priceSats>>(8*i))&0xff))
	}
	payOutput = append(payOutput, 0x19)
	payOutput = append(payOutput, 0x76, 0xa9, 0x14)
	payOutput = append(payOutput, payPkh...)
	payOutput = append(payOutput, 0x88, 0xac)

	// envelopeStart + push(jsonBytes) + OP_ENDIF + OLOCK_PREFIX + push(cancelPkh) + push(payOutput) + OLOCK_SUFFIX
	out := make([]byte, 0, len(envelopeStart)+len(jsonBytes)+4+len(olockPrefixBytes)+1+20+1+len(payOutput)+len(olockSuffixBytes))
	out = append(out, envelopeStart...)
	out = append(out, pushData(jsonBytes)...)
	out = append(out, 0x68)
	out = append(out, olockPrefixBytes...)
	out = append(out, byte(len(cancelPkh))) // direct push 0x14
	out = append(out, cancelPkh...)
	out = append(out, byte(len(payOutput)))
	out = append(out, payOutput...)
	out = append(out, olockSuffixBytes...)

	s := script.Script(out)
	return &s
}

// txWithOutputs wraps multiple locking scripts as 1-sat outputs.
func txWithOutputs(t *testing.T, outputs ...*script.Script) []byte {
	t.Helper()
	tx := transaction.NewTransaction()
	for _, s := range outputs {
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      1,
			LockingScript: s,
		})
	}
	return tx.Bytes()
}

// fillPkh returns a 20-byte pkh stamped with a single byte for test ergonomics.
func fillPkh(b byte) []byte {
	pkh := make([]byte, 20)
	for i := range pkh {
		pkh[i] = b
	}
	return pkh
}

// --- Positive cases ---

// TestOrdLockAdmit_RealBSV21Fixture_ParsesAndAdmits exercises the parser against
// a live mainnet listing. Verifies tokenId, amount, priceSats, payAddress, and
// cancelPkh extraction. This is the byte-parity test — if any part of the
// vendored covenant or parser drifts, this fixture stops parsing.
func TestOrdLockAdmit_RealBSV21Fixture_ParsesAndAdmits(t *testing.T) {
	tm := NewOrdLockTopicManager()
	txData := txWithOutputs(t, scriptFromHex(t, fixtureBSV21TVZNScriptHex))

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result == nil || len(result.OutputsToAdmit) != 1 || result.OutputsToAdmit[0] != 0 {
		t.Fatalf("expected OutputsToAdmit=[0], got %+v", result)
	}

	var entry OrdLockEntry
	if err := json.Unmarshal(result.OutputMetadata[0], &entry); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}

	if entry.Protocol != "bsv-21" {
		t.Errorf("protocol=%q, want bsv-21", entry.Protocol)
	}
	if entry.TokenId != fixtureBSV21TVZNTokenId {
		t.Errorf("tokenId=%q, want %q", entry.TokenId, fixtureBSV21TVZNTokenId)
	}
	if entry.Amount != fixtureBSV21TVZNAmount {
		t.Errorf("amount=%q, want %q", entry.Amount, fixtureBSV21TVZNAmount)
	}
	if entry.PriceSats != fixtureBSV21TVZNPriceSats {
		t.Errorf("priceSats=%d, want %d", entry.PriceSats, fixtureBSV21TVZNPriceSats)
	}
	if entry.CancelPkhHex != fixtureBSV21TVZNCancelPkh {
		t.Errorf("cancelPkhHex=%q, want %q", entry.CancelPkhHex, fixtureBSV21TVZNCancelPkh)
	}
	wantPkh, _ := hex.DecodeString(fixtureBSV21TVZNPayoutPkhHex)
	wantAddr, err := script.NewAddressFromPublicKeyHash(wantPkh, true)
	if err != nil {
		t.Fatalf("derive expected payAddress: %v", err)
	}
	if entry.PayAddress != wantAddr.AddressString {
		t.Errorf("payAddress=%q, want %q", entry.PayAddress, wantAddr.AddressString)
	}
	if entry.AdmittedAt == "" {
		t.Error("admittedAt was not stamped")
	}
	if !strings.HasSuffix(entry.Outpoint, "_0") {
		t.Errorf("outpoint should end with _0, got %q", entry.Outpoint)
	}
}

// TestOrdLockAdmit_SynthBSV20_ParsesAndAdmits covers the BSV-20 (tick) variant.
// No live mainnet BSV-20 fixture exists at the time of writing, so we synthesize
// one through the same builder and verify the parser round-trips.
func TestOrdLockAdmit_SynthBSV20_ParsesAndAdmits(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1000", "tick": "TEST"},
		fillPkh(0xab), fillPkh(0xcd), 50_000_000)
	txData := txWithOutputs(t, scr)

	result, err := tm.Admit(txData, nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result == nil || len(result.OutputsToAdmit) != 1 {
		t.Fatalf("expected one admission, got %+v", result)
	}
	var entry OrdLockEntry
	if err := json.Unmarshal(result.OutputMetadata[0], &entry); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}
	if entry.Protocol != "bsv-20" {
		t.Errorf("protocol=%q, want bsv-20", entry.Protocol)
	}
	if entry.Tick != "TEST" {
		t.Errorf("tick=%q, want TEST", entry.Tick)
	}
	if entry.PriceSats != 50_000_000 {
		t.Errorf("priceSats=%d, want 50_000_000", entry.PriceSats)
	}
	if entry.TokenId != "" {
		t.Errorf("BSV-20 entry should not carry tokenId, got %q", entry.TokenId)
	}
}

// TestOrdLockAdmit_LowercaseTickNormalizedToUpper covers the case-insensitive
// tick rule from N3 — a lowercase tick in the inscription is normalized to
// uppercase canonical form so the lookup filter matches.
func TestOrdLockAdmit_LowercaseTickNormalizedToUpper(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "ordi"},
		fillPkh(0x11), fillPkh(0x22), 1)
	result, err := tm.Admit(txWithOutputs(t, scr), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	var entry OrdLockEntry
	_ = json.Unmarshal(result.OutputMetadata[0], &entry)
	if entry.Tick != "ORDI" {
		t.Errorf("tick should be normalized to ORDI, got %q", entry.Tick)
	}
}

// TestOrdLockAdmit_MultiOutputBatch covers N4 — a single tx with multiple
// OrdLock listing outputs admits all of them.
func TestOrdLockAdmit_MultiOutputBatch(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr1 := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "AAAA"},
		fillPkh(0x01), fillPkh(0x02), 100)
	scr2 := scriptFromHex(t, fixtureBSV21TVZNScriptHex) // BSV-21 fixture
	scr3 := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "5", "tick": "BBBB"},
		fillPkh(0x03), fillPkh(0x04), 200)

	result, err := tm.Admit(txWithOutputs(t, scr1, scr2, scr3), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if len(result.OutputsToAdmit) != 3 {
		t.Fatalf("expected 3 admissions, got %d (%v)", len(result.OutputsToAdmit), result.OutputsToAdmit)
	}
	for _, vout := range []int{0, 1, 2} {
		if result.OutputMetadata[vout] == nil {
			t.Errorf("vout %d should have metadata", vout)
		}
	}
}

// TestOrdLockAdmit_OutpointFormatTxidUnderscoreVout pins down the unique-key
// shape promised to the DEX client per N4(b).
func TestOrdLockAdmit_OutpointFormatTxidUnderscoreVout(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "TEST"},
		fillPkh(0xab), fillPkh(0xcd), 1)
	// Place the OrdLock at vout 1 (after a non-OrdLock) so we can verify the
	// vout suffix is correct, not just always "_0".
	other := scriptFromHex(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	tx, _ := transaction.NewTransactionFromBytes(txWithOutputs(t, other, scr))
	wantTxid := tx.TxID().String()

	result, _ := tm.Admit(txWithOutputs(t, other, scr), nil)
	if len(result.OutputsToAdmit) != 1 || result.OutputsToAdmit[0] != 1 {
		t.Fatalf("expected admission at vout 1, got %v", result.OutputsToAdmit)
	}
	var entry OrdLockEntry
	_ = json.Unmarshal(result.OutputMetadata[1], &entry)
	wantOutpoint := fmt.Sprintf("%s_1", wantTxid)
	if entry.Outpoint != wantOutpoint {
		t.Errorf("outpoint=%q, want %q", entry.Outpoint, wantOutpoint)
	}
}

// --- Rejection cases ---

// TestOrdLockAdmit_RejectsNonOrdLock confirms ordinary scripts are not admitted.
func TestOrdLockAdmit_RejectsNonOrdLock(t *testing.T) {
	tm := NewOrdLockTopicManager()
	plainP2PKH := scriptFromHex(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	opReturn := scriptFromHex(t, "6a046b696c6c")
	result, err := tm.Admit(txWithOutputs(t, plainP2PKH, opReturn), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("non-OrdLock outputs must not admit; got %v", result.OutputsToAdmit)
	}
}

// TestOrdLockAdmit_RejectsZeroAmount enforces the amount >= 1 rule.
func TestOrdLockAdmit_RejectsZeroAmount(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "0", "tick": "TEST"},
		fillPkh(0xab), fillPkh(0xcd), 1)
	result, err := tm.Admit(txWithOutputs(t, scr), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("zero-amount listing must not admit")
	}
}

// TestOrdLockAdmit_RejectsZeroPrice enforces the priceSats >= 1 rule.
func TestOrdLockAdmit_RejectsZeroPrice(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "TEST"},
		fillPkh(0xab), fillPkh(0xcd), 0)
	result, err := tm.Admit(txWithOutputs(t, scr), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("zero-price listing must not admit")
	}
}

// TestOrdLockAdmit_RejectsInvalidTick rejects tick values that don't match the
// 1-4 uppercase-alnum rule. Lowercase is normalized (covered separately) but
// disallowed characters are rejected.
func TestOrdLockAdmit_RejectsInvalidTick(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "TOOLONGTICK"},
		fillPkh(0xab), fillPkh(0xcd), 1)
	result, err := tm.Admit(txWithOutputs(t, scr), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("invalid tick must not admit")
	}
}

// TestOrdLockAdmit_RejectsNon1SatOutput enforces the 1Sat invariant: even a
// byte-perfect OrdLock script is rejected if the output value is not 1 sat.
// Real listings are always 1-sat ordinals; multi-sat covenant outputs would
// confuse the DEX path which assumes ordinal-shape inputs.
func TestOrdLockAdmit_RejectsNon1SatOutput(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "TEST"},
		fillPkh(0xab), fillPkh(0xcd), 100)

	// Build a tx with the OrdLock script at a non-1-sat value.
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      546, // dust-threshold value, definitely not 1
		LockingScript: scr,
	})
	result, err := tm.Admit(tx.Bytes(), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("non-1-sat OrdLock-shaped output must not admit; got %v", result.OutputsToAdmit)
	}
}

// TestOrdLockAdmit_RejectsCorruptedSuffix proves a script that loses the
// covenant suffix is not admitted (covenant integrity check).
func TestOrdLockAdmit_RejectsCorruptedSuffix(t *testing.T) {
	tm := NewOrdLockTopicManager()
	good := scriptFromHex(t, fixtureBSV21TVZNScriptHex)
	corrupted := append([]byte{}, []byte(*good)...)
	// Flip the last byte of the suffix.
	corrupted[len(corrupted)-1] ^= 0xff
	s := script.Script(corrupted)

	result, err := tm.Admit(txWithOutputs(t, &s), nil)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result != nil && len(result.OutputsToAdmit) > 0 {
		t.Errorf("corrupted-suffix listing must not admit")
	}
}

// TestOrdLockAdmit_InvalidTxBytesError surfaces parse errors as before.
func TestOrdLockAdmit_InvalidTxBytesError(t *testing.T) {
	tm := NewOrdLockTopicManager()
	if _, err := tm.Admit([]byte{0x01, 0x02, 0x03}, nil); err == nil {
		t.Fatal("expected error on garbage tx bytes")
	}
}

// --- Spent coin handling ---

// TestOrdLockAdmit_EmitsCoinsRemoved verifies the spend-detection contract:
// a tx that consumes a previously-admitted listing produces a CoinsRemoved
// entry. Combined: admit + remove in one tx.
func TestOrdLockAdmit_EmitsCoinsRemoved(t *testing.T) {
	tm := NewOrdLockTopicManager()
	// Tx that has no OrdLock outputs but is being told it spent a previously-admitted UTXO.
	plain := scriptFromHex(t, "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
	result, err := tm.Admit(txWithOutputs(t, plain), []overlay.AdmittedOutput{
		{Txid: "deadbeef", Vout: 7, Topic: OrdLockTopicName},
	})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result when coins are consumed")
	}
	if len(result.CoinsRemoved) != 1 || result.CoinsRemoved[0] != 0 {
		t.Errorf("CoinsRemoved=%v, want [0]", result.CoinsRemoved)
	}
}

// TestOrdLockAdmit_AdmitAndRemoveInSameTx covers the relist case: a single
// tx both spends an existing listing and creates a new OrdLock listing.
func TestOrdLockAdmit_AdmitAndRemoveInSameTx(t *testing.T) {
	tm := NewOrdLockTopicManager()
	scr := buildOrdLockScriptForTest(t,
		map[string]string{"p": "bsv-20", "op": "transfer", "amt": "1", "tick": "TEST"},
		fillPkh(0xab), fillPkh(0xcd), 100)

	result, err := tm.Admit(txWithOutputs(t, scr), []overlay.AdmittedOutput{
		{Txid: "feedface", Vout: 0, Topic: OrdLockTopicName},
	})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if len(result.OutputsToAdmit) != 1 {
		t.Errorf("expected 1 admission, got %d", len(result.OutputsToAdmit))
	}
	if len(result.CoinsRemoved) != 1 {
		t.Errorf("expected 1 removal, got %d", len(result.CoinsRemoved))
	}
}
