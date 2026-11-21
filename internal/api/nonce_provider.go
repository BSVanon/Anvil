package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync/atomic"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

// WalletNonceProvider mints real 1-satoshi nonce UTXOs from the node wallet.
// Each nonce is a real on-chain output that can only be spent once,
// providing consensus-layer replay protection per merkleworks-x402-spec.
type WalletNonceProvider struct {
	wallet sdk.Interface
}

// NewWalletNonceProvider creates a nonce provider backed by a real wallet.
func NewWalletNonceProvider(w sdk.Interface) *WalletNonceProvider {
	return &WalletNonceProvider{wallet: w}
}

// MintNonce creates a 1-satoshi UTXO via CreateAction and returns its details.
func (w *WalletNonceProvider) MintNonce(ctx context.Context) (*NonceUTXO, error) {
	// Derive a fresh key for this nonce
	keyResult, err := w.wallet.GetPublicKey(ctx, sdk.GetPublicKeyArgs{
		EncryptionArgs: sdk.EncryptionArgs{
			ProtocolID: sdk.Protocol{
				SecurityLevel: sdk.SecurityLevelEveryApp,
				Protocol:      "x402 nonce",
			},
			KeyID:        fmt.Sprintf("nonce-%d", nonceCounter()),
			Counterparty: sdk.Counterparty{Type: sdk.CounterpartyTypeSelf},
		},
	}, "anvil-x402")
	if err != nil {
		return nil, fmt.Errorf("derive nonce key: %w", err)
	}

	// Build P2PKH locking script for the nonce
	addr, err := script.NewAddressFromPublicKey(keyResult.PublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("nonce address: %w", err)
	}
	lockScript, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, fmt.Errorf("nonce script: %w", err)
	}
	lockScriptBytes := []byte(*lockScript)

	// Create a 1-satoshi output via the wallet
	noRandom := false
	result, err := w.wallet.CreateAction(ctx, sdk.CreateActionArgs{
		Description: "x402 nonce UTXO",
		Outputs: []sdk.CreateActionOutput{
			{
				LockingScript:     lockScriptBytes,
				Satoshis:          1,
				OutputDescription: "x402 nonce output",
			},
		},
		Options: &sdk.CreateActionOptions{RandomizeOutputs: &noRandom},
	}, "anvil-x402")
	if err != nil {
		return nil, fmt.Errorf("create nonce UTXO: %w", err)
	}

	// If signable, sign it
	if result.SignableTransaction != nil {
		signResult, err := w.wallet.SignAction(ctx, sdk.SignActionArgs{
			Reference: result.SignableTransaction.Reference,
		}, "anvil-x402")
		if err != nil {
			return nil, fmt.Errorf("sign nonce UTXO: %w", err)
		}
		vout, err := nonceOutputIndex(signResult.Tx, lockScriptBytes)
		if err != nil {
			return nil, err
		}
		return &NonceUTXO{
			TxID:             signResult.Txid.String(),
			Vout:             vout,
			Satoshis:         1,
			LockingScriptHex: hex.EncodeToString(lockScriptBytes),
		}, nil
	}

	vout, err := nonceOutputIndex(result.Tx, lockScriptBytes)
	if err != nil {
		return nil, err
	}
	return &NonceUTXO{
		TxID:             result.Txid.String(),
		Vout:             vout,
		Satoshis:         1,
		LockingScriptHex: hex.EncodeToString(lockScriptBytes),
	}, nil
}

// nonceOutputIndex locates the nonce when the wallet returns transaction
// bytes. A canonical wallet may omit them; RandomizeOutputs=false then makes
// the requested output vout 0.
func nonceOutputIndex(raw, scriptBytes []byte) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		return 0, fmt.Errorf("parse nonce transaction: %w", err)
	}
	for i, out := range tx.Outputs {
		if out.Satoshis == 1 && out.LockingScript != nil && bytes.Equal(*out.LockingScript, scriptBytes) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("created transaction has no nonce output")
}

var nonceSeq atomic.Uint64

func nonceCounter() uint64 {
	return nonceSeq.Add(1)
}
