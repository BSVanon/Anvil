package api

import (
	"encoding/hex"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// buildSignedNonceTx creates a real P2PKH transaction that spends a nonce UTXO
// with a valid signature. Returns the signed tx, the nonce UTXO details, and the key.
func buildSignedNonceTx(t *testing.T) (*transaction.Transaction, *NonceUTXO, *ec.PrivateKey) {
	t.Helper()

	// Generate a key pair
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Build the P2PKH locking script for the nonce UTXO
	addr, err := bsvscript.NewAddressFromPublicKey(key.PubKey(), true)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		t.Fatalf("build lock script: %v", err)
	}
	lockScriptHex := hex.EncodeToString([]byte(*lockScript))

	// Create a fake "source transaction" that the nonce UTXO lives in
	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      1000,
		LockingScript: lockScript,
	})
	sourceTxID := sourceTx.TxID()

	nonce := &NonceUTXO{
		TxID:             sourceTxID.String(),
		Vout:             0,
		Satoshis:         1000,
		LockingScriptHex: lockScriptHex,
	}

	// Build the spending transaction
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{
		SourceTXID:          sourceTxID,
		SourceTxOutIndex:    0,
		SequenceNumber:      0xffffffff,
		SourceTransaction:   sourceTx,
	})

	// Add a payee output
	payeeScript, _ := hex.DecodeString("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac")
	ls := bsvscript.Script(payeeScript)
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      500,
		LockingScript: &ls,
	})

	// Sign with the real key
	unlock, err := p2pkh.Unlock(key, nil)
	if err != nil {
		t.Fatalf("create unlock template: %v", err)
	}
	tx.Inputs[0].UnlockingScriptTemplate = unlock
	if err := tx.Sign(); err != nil {
		t.Fatalf("sign tx: %v", err)
	}

	return tx, nonce, key
}

func TestVerifyNonceInputSignature_ValidSig(t *testing.T) {
	tx, nonce, _ := buildSignedNonceTx(t)

	err := verifyNonceInputSignature(tx, nonce)
	if err != nil {
		t.Fatalf("valid signature should pass: %v", err)
	}
}

func TestVerifyNonceInputSignature_ForgedSig(t *testing.T) {
	tx, nonce, _ := buildSignedNonceTx(t)

	// Forge the unlocking script by replacing it with garbage
	forgedScript := bsvscript.Script([]byte{0x00, 0x48, 0x30, 0x45}) // garbage bytes
	tx.Inputs[0].UnlockingScript = &forgedScript

	err := verifyNonceInputSignature(tx, nonce)
	if err == nil {
		t.Fatal("forged signature should be rejected")
	}
	t.Logf("correctly rejected forged sig: %v", err)
}

func TestVerifyNonceInputSignature_EmptyUnlockScript(t *testing.T) {
	tx, nonce, _ := buildSignedNonceTx(t)

	// Remove the unlocking script entirely
	emptyScript := bsvscript.Script([]byte{})
	tx.Inputs[0].UnlockingScript = &emptyScript

	err := verifyNonceInputSignature(tx, nonce)
	if err == nil {
		t.Fatal("empty unlocking script should be rejected")
	}
}

func TestVerifyNonceInputSignature_WrongKey(t *testing.T) {
	_, nonce, _ := buildSignedNonceTx(t)

	// Sign with a DIFFERENT key — the signature will be structurally valid
	// but for the wrong public key, so P2PKH verification should fail
	wrongKey, _ := ec.NewPrivateKey()
	wrongTx := transaction.NewTransaction()

	// Rebuild the source tx for proper signing context
	lockBytes, _ := hex.DecodeString(nonce.LockingScriptHex)
	lockScript := bsvscript.Script(lockBytes)
	sourceTxID, _ := chainhash.NewHashFromHex(nonce.TxID)

	sourceTx := transaction.NewTransaction()
	sourceTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(nonce.Satoshis),
		LockingScript: &lockScript,
	})

	wrongTx.AddInput(&transaction.TransactionInput{
		SourceTXID:        sourceTxID,
		SourceTxOutIndex:  0,
		SequenceNumber:    0xffffffff,
		SourceTransaction: sourceTx,
	})
	payeeScript, _ := hex.DecodeString("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac")
	ls := bsvscript.Script(payeeScript)
	wrongTx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      500,
		LockingScript: &ls,
	})

	unlock, _ := p2pkh.Unlock(wrongKey, nil)
	wrongTx.Inputs[0].UnlockingScriptTemplate = unlock
	_ = wrongTx.Sign()

	err := verifyNonceInputSignature(wrongTx, nonce)
	if err == nil {
		t.Fatal("signature with wrong key should be rejected")
	}
	t.Logf("correctly rejected wrong-key sig: %v", err)
}

func TestVerifyNonceInputSignature_NonceNotFound(t *testing.T) {
	tx, _, _ := buildSignedNonceTx(t)

	// Point to a different nonce UTXO that doesn't exist in the tx
	wrongNonce := &NonceUTXO{
		TxID:             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Vout:             0,
		Satoshis:         1000,
		LockingScriptHex: "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
	}

	err := verifyNonceInputSignature(tx, wrongNonce)
	if err == nil {
		t.Fatal("should reject when nonce input not found in tx")
	}
}
