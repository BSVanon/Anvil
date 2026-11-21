package main

import (
	"fmt"
	"log"
	"log/slog"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
)

type paymentWallet interface {
	Wallet() sdkwallet.Interface
}

// wireX402Payment derives the node payee and wires the deprecated proof-only
// nonce provider when enabled. The proof-off path never opens the wallet.
func wireX402Payment(apiCfg config.APIConfig, identityWIF string, nodeWallet paymentWallet, logger *slog.Logger) (int, string, api.NonceProvider, error) {
	paymentSatoshis := apiCfg.PaymentSatoshis
	if apiCfg.X402ProofScheme {
		api.ConfigureMintBudget(apiCfg.X402MintBurst, apiCfg.X402MintsPerMinute)
	} else {
		log.Printf("x402: proof scheme off; no challenge coins are minted")
	}

	if identityWIF != "" && nodeWallet != nil {
		payeeKey, err := ec.PrivateKeyFromWif(identityWIF)
		if err != nil {
			return 0, "", nil, fmt.Errorf("x402: invalid identity WIF: %w", err)
		}
		addr, err := script.NewAddressFromPublicKey(payeeKey.PubKey(), true)
		if err != nil {
			return 0, "", nil, fmt.Errorf("x402: derive address: %w", err)
		}
		lockScript, err := p2pkh.Lock(addr)
		if err != nil {
			return 0, "", nil, fmt.Errorf("x402: build locking script: %w", err)
		}
		payeeScriptHex := fmt.Sprintf("%x", []byte(*lockScript))
		if !apiCfg.X402ProofScheme {
			return paymentSatoshis, payeeScriptHex, nil, nil
		}

		walletNonce := api.NewWalletNonceProvider(nodeWallet.Wallet())
		if paymentSatoshis > 0 {
			poolSize := apiCfg.NoncePoolSize
			if poolSize <= 0 {
				poolSize = 100
			}
			provider := api.NewUTXONoncePool(walletNonce, poolSize, logger)
			log.Printf("x402: payment gating enabled (%d sats/request, payee=%s, nonce pool=%d)", paymentSatoshis, addr.AddressString, poolSize)
			return paymentSatoshis, payeeScriptHex, provider, nil
		}
		log.Printf("x402: node is free, nonces minted on demand (no pre-mint pool)")
		return paymentSatoshis, payeeScriptHex, walletNonce, nil
	}

	if paymentSatoshis > 0 {
		log.Printf("x402: payment_satoshis=%d but identity.wif or wallet missing — payment gating DISABLED", paymentSatoshis)
		paymentSatoshis = 0
	}
	return paymentSatoshis, "", nil, nil
}
