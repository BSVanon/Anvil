package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/txrelay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// buildSignedDirectPaymentTx builds a real, validly-signed P2PKH transaction
// paying paySats to payeeScriptHex, with its input's source output embedded
// (SourceTransaction) the same way buildSignedNonceTx (payment_spv_test.go)
// does for the challenge-proof path, and the same way an Extended
// Format/BEEF-encoded X-Bsv-Payment arrives in production
// (transaction/input.go's ReadFrom sets this via SetSourceTxOutput when
// extended==true).
func buildSignedDirectPaymentTx(t *testing.T, payeeScriptHex string, paySats uint64) *transaction.Transaction {
	t.Helper()

	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr, err := bsvscript.NewAddressFromPublicKey(key.PubKey(), true)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		t.Fatalf("build lock script: %v", err)
	}

	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: lockScript,
	})
	sourceTxID := sourceTx.TxID()

	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:        sourceTxID,
		SourceTxOutIndex:  0,
		SequenceNumber:    0xffffffff,
		SourceTransaction: sourceTx,
	})

	payeeBytes, err := hex.DecodeString(payeeScriptHex)
	if err != nil {
		t.Fatalf("decode payee script: %v", err)
	}
	ls := bsvscript.Script(payeeBytes)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      paySats,
		LockingScript: &ls,
	})

	unlock, err := p2pkh.Unlock(key, nil)
	if err != nil {
		t.Fatalf("create unlock template: %v", err)
	}
	tx.Inputs[0].UnlockingScriptTemplate = unlock
	if err := tx.Sign(); err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	return tx
}

// mockARCServer returns an httptest.Server that answers every ARC submit
// with SEEN_ON_NETWORK, and a *txrelay.ARCClient pointed at it.
func mockARCServer(t *testing.T) *txrelay.ARCClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(txrelay.ARCResponse{TxID: "mock", Status: "SEEN_ON_NETWORK"})
	}))
	t.Cleanup(srv.Close)
	return txrelay.NewARCClient(srv.URL, "")
}

// TestDirectPaymentRejectsUnsignedTxNoARC: an X-Bsv-Payment with correct
// outputs but no input signature at all, on a node with no ARC client, is
// refused before it is decoded: such a node takes no direct payment.
func TestDirectPaymentRejectsUnsignedTxNoARC(t *testing.T) {
	payeeScript := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: payeeScript,
		NonceProvider:  &DevNonceProvider{},
		// No ARC client.
	})

	payeeBytes, _ := hex.DecodeString(payeeScript)
	txHex := hex.EncodeToString(buildRawTx(payeeBytes, 100)) // no unlocking script, no embedded source output
	_, err := pg.verifyDirectPayment(txHex, []Payee{{Role: "infrastructure", LockingScriptHex: payeeScript, AmountSats: 100}})
	if !errors.Is(err, errDirectPaymentUnavailable) {
		t.Fatalf("an unsigned direct payment on a node with no ARC client: want errDirectPaymentUnavailable, got %v", err)
	}
}

// TestDirectPaymentRejectsUnsignedTxWithARC: the same unsigned transaction
// must be rejected by Anvil's OWN verification even when an ARC client IS
// configured — "verify the payment tx's scripts and signatures the same
// way whether or not ARC is configured," not "rely on ARC to catch it."
func TestDirectPaymentRejectsUnsignedTxWithARC(t *testing.T) {
	payeeScript := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: payeeScript,
		NonceProvider:  &DevNonceProvider{},
		ARCClient:      mockARCServer(t), // would happily accept this via SEEN_ON_NETWORK if asked
	})

	payeeBytes, _ := hex.DecodeString(payeeScript)
	txHex := hex.EncodeToString(buildRawTx(payeeBytes, 100))
	_, err := pg.verifyDirectPayment(txHex, []Payee{{Role: "infrastructure", LockingScriptHex: payeeScript, AmountSats: 100}})
	if err == nil {
		t.Fatal("an unsigned transaction must be rejected by Anvil's own check even when ARC is configured")
	}
	t.Logf("correctly rejected unsigned tx despite ARC being configured: %v", err)
}

// TestDirectPaymentAcceptsSignedTxWithARC: a genuinely signed payment is
// accepted and broadcast when ARC is configured — confirms the new input
// check does not also break the honest path when ARC is present.
func TestDirectPaymentAcceptsSignedTxWithARC(t *testing.T) {
	payeeScript := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: payeeScript,
		NonceProvider:  &DevNonceProvider{},
		ARCClient:      mockARCServer(t),
	})

	tx := buildSignedDirectPaymentTx(t, payeeScript, 100)
	efHex, err := tx.EFHex()
	if err != nil {
		t.Fatalf("serialize extended format: %v", err)
	}
	receipt, err := pg.verifyDirectPayment(efHex, []Payee{{Role: "infrastructure", LockingScriptHex: payeeScript, AmountSats: 100}})
	if err != nil {
		t.Fatalf("a validly signed direct payment should be accepted with ARC configured: %v", err)
	}
	if receipt.Satoshis != 100 {
		t.Fatalf("expected 100 sats in receipt, got %d", receipt.Satoshis)
	}
}

// TestDirectPaymentRejectsForgedSignature: correct outputs and an embedded
// source output, but a garbage unlocking script in place of a real
// signature, must be rejected, even by a node whose ARC would accept it.
func TestDirectPaymentRejectsForgedSignature(t *testing.T) {
	payeeScript := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: payeeScript,
		NonceProvider:  &DevNonceProvider{},
		ARCClient:      mockARCServer(t),
	})

	tx := buildSignedDirectPaymentTx(t, payeeScript, 100)
	forged := bsvscript.Script([]byte{0x00, 0x48, 0x30, 0x45}) // garbage, not a signature
	tx.Inputs[0].UnlockingScript = &forged

	efHex, err := tx.EFHex()
	if err != nil {
		t.Fatalf("serialize extended format: %v", err)
	}
	_, err = pg.verifyDirectPayment(efHex, []Payee{{Role: "infrastructure", LockingScriptHex: payeeScript, AmountSats: 100}})
	if err == nil {
		t.Fatal("a forged unlocking script must be rejected")
	}
	t.Logf("correctly rejected forged signature: %v", err)
}

// TestDirectPaymentRejectsTooManyInputs: a transaction with more than
// maxDirectPaymentInputs inputs is refused outright, before running the
// interpreter on any of them — bounding the worst-case verification time.
func TestDirectPaymentRejectsTooManyInputs(t *testing.T) {
	payeeScript := testPayeeScript(t)
	tx := buildSignedDirectPaymentTx(t, payeeScript, 100)
	// Pad with plain, unsigned inputs with no source output (cheap to build) —
	// over the cap, verifyDirectPaymentInputs must refuse before verifying any
	// of them individually.
	for i := 0; i < maxDirectPaymentInputs; i++ {
		tx.Inputs = append(tx.Inputs, tx.Inputs[0])
	}
	if len(tx.Inputs) <= maxDirectPaymentInputs {
		t.Fatalf("test setup error: need more than %d inputs, got %d", maxDirectPaymentInputs, len(tx.Inputs))
	}

	err := verifyDirectPaymentInputs(tx)
	if err == nil {
		t.Fatal("a transaction over maxDirectPaymentInputs must be refused")
	}
	t.Logf("correctly refused too many inputs: %v", err)
}

// TestDirectPaymentRejectsNoEmbeddedSourceOutput: an input with a
// present, well-formed-looking unlocking script but NO embedded source
// output (a plain/legacy-format transaction, not extended format/BEEF)
// must be refused as unverifiable rather than silently trusted.
func TestDirectPaymentRejectsNoEmbeddedSourceOutput(t *testing.T) {
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:       nil,
		SourceTxOutIndex: 0,
		SequenceNumber:   0xffffffff,
	})
	fakeSig := bsvscript.Script(make([]byte, 70)) // present, but no source output to check it against
	tx.Inputs[0].UnlockingScript = &fakeSig

	err := verifyDirectPaymentInputs(tx)
	if err == nil {
		t.Fatal("an input with no embedded source output must be refused")
	}
	t.Logf("correctly refused missing source output: %v", err)
}

// TestDirectPaymentRejectsTxAlteredAfterSigning: a payment changed after it
// was signed still carries a well-formed P2PKH unlocking script, but its
// signature covers a different transaction, so the interpreter's signature
// check refuses it, even on a node whose ARC would accept it. Each change is
// made to a transaction that passes the input check as signed.
func TestDirectPaymentRejectsTxAlteredAfterSigning(t *testing.T) {
	payeeScript := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats:      100,
		PayeeScriptHex: payeeScript,
		NonceProvider:  &DevNonceProvider{},
		ARCClient:      mockARCServer(t),
	})
	payees := []Payee{{Role: "infrastructure", LockingScriptHex: payeeScript, AmountSats: 100}}
	alterations := map[string]func(tx *transaction.Transaction){
		"payee output raised from 1 to 100 sats": func(tx *transaction.Transaction) { tx.Outputs[0].Satoshis = 100 },
		"output added after signing": func(tx *transaction.Transaction) {
			tx.AddOutput(scriptOutput(t, payeeScript, 100))
		},
	}
	for name, alter := range alterations {
		tx := buildSignedDirectPaymentTx(t, payeeScript, 1)
		if err := verifyDirectPaymentInputs(tx); err != nil {
			t.Fatalf("%s: the transaction as signed should pass the input check: %v", name, err)
		}
		alter(tx)
		efHex, err := tx.EFHex()
		if err != nil {
			t.Fatalf("%s: serialize extended format: %v", name, err)
		}
		if _, err := pg.verifyDirectPayment(efHex, payees); err == nil {
			t.Fatalf("%s: a payment altered after signing must be refused", name)
		}
	}
}
