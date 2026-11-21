package api

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

// nonceTestWallet is the node's wallet as WalletNonceProvider uses it: keys
// derived from a root key by go-sdk's ProtoWallet, and a CreateAction that
// answers with a txid for the nonce output, with no chain behind it. It
// records the key IDs it derived. Every other wallet method is unused here.
type nonceTestWallet struct {
	sdk.Interface
	proto  *sdk.ProtoWallet
	mu     sync.Mutex
	keyIDs []string
}

func (w *nonceTestWallet) GetPublicKey(ctx context.Context, args sdk.GetPublicKeyArgs, originator string) (*sdk.GetPublicKeyResult, error) {
	w.mu.Lock()
	w.keyIDs = append(w.keyIDs, args.KeyID)
	w.mu.Unlock()
	return w.proto.GetPublicKey(ctx, args, originator)
}

func (w *nonceTestWallet) CreateAction(_ context.Context, args sdk.CreateActionArgs, _ string) (*sdk.CreateActionResult, error) {
	return &sdk.CreateActionResult{Txid: chainhash.Hash(sha256.Sum256(args.Outputs[0].LockingScript))}, nil
}

func (w *nonceTestWallet) lastKeyID() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.keyIDs[len(w.keyIDs)-1]
}

// TestProofRoundTripWithWalletNonceProvider runs the challenge and proof
// through the production nonce provider. Its nonce output is P2PKH to a key
// the node's wallet derives for itself (BRC-42, counterparty self,
// nonce_provider.go), so verifyProof runs the nonce checks the dev provider
// skips: the proof must spend that outpoint, with a valid signature.
//
// Two limits are shown here. The signature that passes is made with the
// node's own derived key: a payer without the node's root key cannot sign
// the nonce input, and is refused. And the passing transaction spends a
// 1-sat nonce to pay 100 sats: with require_mempool off, the default, nothing
// checks the transaction's balance or any input other than the nonce.
func TestProofRoundTripWithWalletNonceProvider(t *testing.T) {
	useMintBudget(t)
	defaultMintBudget = newMintBudget(10, 60, time.Now)
	root, _ := ec.NewPrivateKey()
	proto, err := sdk.NewProtoWallet(sdk.ProtoWalletArgs{Type: sdk.ProtoWalletArgsTypePrivateKey, PrivateKey: root})
	if err != nil {
		t.Fatalf("proto wallet: %v", err)
	}
	wallet := &nonceTestWallet{proto: proto}
	srv := testServer(t)
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: NewWalletNonceProvider(wallet),
	})
	srv.mux = http.NewServeMux()
	srv.routes()
	pay := func(ch *X402Challenge, key *ec.PrivateKey) *httptest.ResponseRecorder {
		tx := nonceSpend(t, ch.NonceUTXO, key, 1, 100, testPayeeScript(t), nil)
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		req.Host = "localhost"
		req.Header.Set(HeaderX402Proof, proofForTx(t, ch, tx))
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	ch := getChallenge(t, srv, http.MethodGet, "/status")
	if ch.NonceUTXO == nil || ch.NonceUTXO.LockingScriptHex == "dev-mode-no-real-utxo" {
		t.Fatalf("the challenge should carry a wallet-minted nonce, got %+v", ch.NonceUTXO)
	}
	nonceKey, err := sdk.NewKeyDeriver(root).DerivePrivateKey(
		sdk.Protocol{SecurityLevel: sdk.SecurityLevelEveryApp, Protocol: "x402 nonce"},
		wallet.lastKeyID(), sdk.Counterparty{Type: sdk.CounterpartyTypeSelf})
	if err != nil {
		t.Fatalf("derive the nonce key: %v", err)
	}
	if w := pay(ch, nonceKey); w.Code != http.StatusOK {
		t.Fatalf("a nonce spend signed with the node's derived key: got %d %s, want 200", w.Code, w.Body.String())
	}

	stranger, _ := ec.NewPrivateKey()
	ch = getChallenge(t, srv, http.MethodGet, "/status")
	if w := pay(ch, stranger); w.Code != http.StatusPaymentRequired {
		t.Fatalf("a nonce spend signed by a key other than the node's: got %d %s, want 402", w.Code, w.Body.String())
	}
}
