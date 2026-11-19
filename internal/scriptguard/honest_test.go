package scriptguard

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	crypto "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

var chainhashOne = chainhash.Hash{1}

// spend is one input of a transaction, with the output it spends.
type spend struct {
	tx      *transaction.Transaction
	vin     int
	prevout *transaction.TransactionOutput
}

func newKey(t testing.TB) *ec.PrivateKey {
	t.Helper()
	k, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func p2pkhLock(t testing.TB, k *ec.PrivateKey) *script.Script {
	t.Helper()
	addr, err := script.NewAddressFromPublicKey(k.PubKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p2pkh.Lock(addr)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// parentOf returns a transaction paying outs, spending a fixed outpoint.
func parentOf(outs ...*transaction.TransactionOutput) *transaction.Transaction {
	prev := script.Script{}
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &chainhashOne, UnlockingScript: &prev, SequenceNumber: transaction.DefaultSequenceNumber})
	for _, o := range outs {
		tx.AddOutput(o)
	}
	return tx
}

// spendOf returns a transaction spending output 0 of parent into outs, and
// the spend of its input 0.
func spendOf(parent *transaction.Transaction, outs ...*transaction.TransactionOutput) spend {
	tx := transaction.NewTransaction()
	tx.AddInputFromTx(parent, 0, nil)
	for _, o := range outs {
		tx.AddOutput(o)
	}
	return spend{tx: tx, vin: 0, prevout: parent.Outputs[0]}
}

// sign returns k's signature over input vin of tx, with flag appended.
func sign(t testing.TB, tx *transaction.Transaction, vin int, k *ec.PrivateKey, flag sighash.Flag) []byte {
	t.Helper()
	h, err := tx.CalcInputSignatureHash(uint32(vin), flag)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := k.Sign(h)
	if err != nil {
		t.Fatal(err)
	}
	return append(sig.Serialize(), byte(flag))
}

func pushes(items ...[]byte) *script.Script {
	s := &script.Script{}
	for _, it := range items {
		_ = s.AppendPushData(it)
	}
	return s
}

func changeOut(t testing.TB) *transaction.TransactionOutput {
	return &transaction.TransactionOutput{LockingScript: p2pkhLock(t, newKey(t)), Satoshis: 900}
}

// p2pkhSpend spends a P2PKH output with the go-sdk p2pkh template.
func p2pkhSpend(t testing.TB) spend {
	k := newKey(t)
	s := spendOf(parentOf(&transaction.TransactionOutput{LockingScript: p2pkhLock(t, k), Satoshis: 1000}), changeOut(t))
	unlocker, err := p2pkh.Unlock(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.tx.Inputs[0].UnlockingScript, err = unlocker.Sign(s.tx, 0); err != nil {
		t.Fatal(err)
	}
	return s
}

var pushDropProtocol = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: "scriptguard test"}

// pushDropSpend spends a go-sdk pushdrop template output holding fields of
// the given sizes, signed through the template's unlocker.
func pushDropSpend(t testing.TB, sizes ...int) spend {
	t.Helper()
	w, err := wallet.NewCompletedProtoWallet(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	var fields [][]byte
	for i, n := range sizes {
		f := make([]byte, n)
		for j := range f {
			f[j] = byte(i + j)
		}
		fields = append(fields, f)
	}
	pd := &pushdrop.PushDrop{Wallet: w}
	self := wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}
	lock, err := pd.Lock(context.Background(), fields, pushDropProtocol, "1", self, true, true, pushdrop.LockBefore)
	if err != nil {
		t.Fatal(err)
	}
	s := spendOf(parentOf(&transaction.TransactionOutput{LockingScript: lock, Satoshis: 1000}), changeOut(t))
	unlock, err := pd.Unlock(context.Background(), pushDropProtocol, "1", self, wallet.SignOutputsAll, false).Sign(s.tx, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.tx.Inputs[0].UnlockingScript = unlock
	return s
}

// ordEnvelope is the 1Sat inscription envelope a BSV-21 transfer output
// starts with: OP_0 OP_IF "ord" OP_1 "application/bsv-20" OP_0 <json> OP_ENDIF.
func ordEnvelope(json string) []byte {
	s := script.Script{script.OpFALSE, script.OpIF}
	_ = s.AppendPushData([]byte("ord"))
	s = append(s, script.Op1)
	_ = s.AppendPushData([]byte("application/bsv-20"))
	s = append(s, script.OpFALSE)
	_ = s.AppendPushData([]byte(json))
	return append(s, script.OpENDIF)
}

const bsv21JSON = `{"p":"bsv-20","op":"transfer","id":"ae59f3b898ec61acbdb6cc7a245fabeded0c094bf046f35206a3aec60ef88127_0","amt":"1000"}`

// bsv21Spend spends a BSV-21 transfer output: the envelope, then P2PKH.
func bsv21Spend(t testing.TB) spend {
	k := newKey(t)
	lock := script.Script(append(ordEnvelope(bsv21JSON), *p2pkhLock(t, k)...))
	s := spendOf(parentOf(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1}), changeOut(t))
	unlocker, _ := p2pkh.Unlock(k, nil)
	var err error
	if s.tx.Inputs[0].UnlockingScript, err = unlocker.Sign(s.tx, 0); err != nil {
		t.Fatal(err)
	}
	return s
}

// mneeSpend spends an output of the MNEE cosign shape that
// Anvil-Swap/src/avos/mnee-output-template.ts records from mainnet: the
// envelope, OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIGVERIFY
// <cosigner> OP_CHECKSIG. The cosigner is a test key, not MNEE's.
func mneeSpend(t testing.TB) spend {
	owner, cosigner := newKey(t), newKey(t)
	lock := script.Script(ordEnvelope(bsv21JSON))
	lock = append(lock, script.OpDUP, script.OpHASH160)
	_ = lock.AppendPushData(crypto.Hash160(owner.PubKey().Compressed()))
	lock = append(lock, script.OpEQUALVERIFY, script.OpCHECKSIGVERIFY)
	_ = lock.AppendPushData(cosigner.PubKey().Compressed())
	lock = append(lock, script.OpCHECKSIG)
	s := spendOf(parentOf(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1}), changeOut(t))
	s.tx.Inputs[0].UnlockingScript = pushes(
		sign(t, s.tx, 0, cosigner, sighash.AllForkID),
		sign(t, s.tx, 0, owner, sighash.AllForkID),
		owner.PubKey().Compressed())
	return s
}

// ordLockScript builds an OrdLock listing script the way
// topics.ParseOrdLockScript reads it: the envelope, OLOCK_PREFIX, the
// cancel pkh, the pay output, OLOCK_SUFFIX.
func ordLockScript(t testing.TB, cancel *ec.PrivateKey, pay *transaction.TransactionOutput) *script.Script {
	t.Helper()
	prefix, err := hex.DecodeString(topics.OLOCK_PREFIX_HEX)
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := hex.DecodeString(topics.OLOCK_SUFFIX_HEX)
	if err != nil {
		t.Fatal(err)
	}
	s := script.Script(ordEnvelope(bsv21JSON))
	s = append(s, prefix...)
	_ = s.AppendPushData(crypto.Hash160(cancel.PubKey().Compressed()))
	_ = s.AppendPushData(pay.Bytes())
	s = append(s, suffix...)
	if topics.ParseOrdLockScript(s) == nil {
		t.Fatal("test OrdLock script does not parse as an OrdLock listing")
	}
	return &s
}

// ordLockSpends returns an OrdLock purchase (the covenant's preimage path,
// js-1sat-ord's purchaseOrdTokenListing shape) and a cancel (the seller's
// signature path), each of its own listing.
func ordLockSpends(t testing.TB) (purchase, cancel spend) {
	seller, payee, buyer := newKey(t), newKey(t), newKey(t)
	pay := &transaction.TransactionOutput{LockingScript: p2pkhLock(t, payee), Satoshis: 5000}
	listing := &transaction.TransactionOutput{LockingScript: ordLockScript(t, seller, pay), Satoshis: 1}

	tokenLock := script.Script(append(ordEnvelope(bsv21JSON), *p2pkhLock(t, buyer)...))
	token := &transaction.TransactionOutput{LockingScript: &tokenLock, Satoshis: 1}
	change := changeOut(t)
	purchase = spendOf(parentOf(listing), token, pay, change)
	pre, err := purchase.tx.CalcInputPreimage(0, sighash.AllForkID|sighash.AnyOneCanPay)
	if err != nil {
		t.Fatal(err)
	}
	unlock := pushes(token.Bytes(), change.Bytes(), pre)
	*unlock = append(*unlock, script.OpFALSE)
	purchase.tx.Inputs[0].UnlockingScript = unlock

	cancel = spendOf(parentOf(listing), token, change)
	cancel.tx.Inputs[0].UnlockingScript = pushes(
		sign(t, cancel.tx, 0, seller, sighash.AllForkID), seller.PubKey().Compressed())
	*cancel.tx.Inputs[0].UnlockingScript = append(*cancel.tx.Inputs[0].UnlockingScript, script.Op1)
	return purchase, cancel
}
