package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BSVanon/Anvil/internal/api"
	"github.com/BSVanon/Anvil/internal/config"
	sdkwallet "github.com/bsv-blockchain/go-sdk/wallet"
)

const paymentTestWIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S"

type countedPaymentWallet struct {
	calls atomic.Int64
	w     sdkwallet.Interface
}

func (w *countedPaymentWallet) Wallet() sdkwallet.Interface {
	w.calls.Add(1)
	return w.w
}

// rejectingSDKWallet embeds the full wallet interface and overrides the only
// method a background pool refill reaches, so the startup test stays local.
type rejectingSDKWallet struct{ sdkwallet.Interface }

func (rejectingSDKWallet) GetPublicKey(context.Context, sdkwallet.GetPublicKeyArgs, string) (*sdkwallet.GetPublicKeyResult, error) {
	return nil, errors.New("test wallet does not mint")
}

func TestWireX402PaymentOffDoesNotOpenWalletOrBuildProvider(t *testing.T) {
	var logs bytes.Buffer
	var backgroundLogs bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&backgroundLogs, nil)))
	log.SetOutput(&logs)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		slog.SetDefault(oldLogger)
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	})

	wallet := &countedPaymentWallet{w: rejectingSDKWallet{}}
	sats, payee, provider, err := wireX402Payment(config.APIConfig{
		PaymentSatoshis: 100, X402ProofScheme: false, NoncePoolSize: 1,
	}, paymentTestWIF, wallet, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if sats != 100 || payee == "" || provider != nil || wallet.calls.Load() != 0 {
		t.Fatalf("proof-off wiring touched nonce wallet: sats=%d payee=%q provider=%T wallet_calls=%d", sats, payee, provider, wallet.calls.Load())
	}
	const line = "x402: proof scheme off; no challenge coins are minted"
	if strings.Count(logs.String(), line) != 1 {
		t.Fatalf("proof-off startup log count = %d: %q", strings.Count(logs.String(), line), logs.String())
	}
	if strings.Contains(backgroundLogs.String(), "nonce mint budget") || strings.Contains(backgroundLogs.String(), "nonce pool") {
		t.Fatalf("proof-off startup began mint background work: %q", backgroundLogs.String())
	}
}

func TestWireX402PaymentSwitchKeepsPayeeScript(t *testing.T) {
	offWallet := &countedPaymentWallet{w: rejectingSDKWallet{}}
	onWallet := &countedPaymentWallet{w: rejectingSDKWallet{}}
	offSats, offPayee, offProvider, err := wireX402Payment(config.APIConfig{
		PaymentSatoshis: 100, X402ProofScheme: false, NoncePoolSize: 1,
	}, paymentTestWIF, offWallet, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	onSats, onPayee, onProvider, err := wireX402Payment(config.APIConfig{
		PaymentSatoshis: 100, X402ProofScheme: true, NoncePoolSize: 1,
	}, paymentTestWIF, onWallet, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if offSats != onSats || offPayee == "" || offPayee != onPayee {
		t.Fatalf("switch changed payment inputs: off=(%d,%q) on=(%d,%q)", offSats, offPayee, onSats, onPayee)
	}
	if offProvider != nil || onProvider == nil || offWallet.calls.Load() != 0 || onWallet.calls.Load() != 1 {
		t.Fatalf("provider wiring mismatch: off=%T on=%T off_wallet=%d on_wallet=%d",
			offProvider, onProvider, offWallet.calls.Load(), onWallet.calls.Load())
	}
}

func TestWireX402PaymentOnKeepsPoolAndOnDemandRules(t *testing.T) {
	for _, tc := range []struct {
		name     string
		price    int
		wantPool bool
	}{
		{name: "charging pool", price: 100, wantPool: true},
		{name: "free on demand", price: 0, wantPool: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wallet := &countedPaymentWallet{w: rejectingSDKWallet{}}
			_, payee, provider, err := wireX402Payment(config.APIConfig{
				PaymentSatoshis: tc.price, X402ProofScheme: true, NoncePoolSize: 1,
			}, paymentTestWIF, wallet, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			if payee == "" || provider == nil || wallet.calls.Load() != 1 {
				t.Fatalf("proof-on wiring incomplete: payee=%q provider=%T wallet_calls=%d", payee, provider, wallet.calls.Load())
			}
			_, isPool := provider.(*api.UTXONoncePool)
			_, isOnDemand := provider.(*api.WalletNonceProvider)
			if isPool != tc.wantPool || isOnDemand == tc.wantPool {
				t.Fatalf("price=%d provider=%T, want pool=%v", tc.price, provider, tc.wantPool)
			}
		})
	}
}
