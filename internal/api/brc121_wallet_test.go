package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	anvilwallet "github.com/BSVanon/Anvil/internal/wallet"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk"
)

// realBRC121Node is a payment gate taking BRC-121 into a real node wallet,
// built as the node builds it (wallet.New in a data directory, its header
// store, proof store and broadcaster), with a mock ARC behind both.
type realBRC121Node struct {
	pg     *PaymentGate
	nw     *anvilwallet.NodeWallet
	arc    *brc121ARC
	payer  *brc121Payer
	server *ec.PublicKey
}

func newRealBRC121Node(t *testing.T) *realBRC121Node {
	t.Helper()
	payer := newBRC121Payer()
	hs := brc121HeaderStore(t, payer.source)
	ps, err := spv.NewProofStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ps.Close() })
	arc, client := newBRC121Stub()
	broadcaster := txrelay.NewBroadcaster(txrelay.NewMempool(), client, slog.Default())
	key, _ := ec.NewPrivateKey()
	nw, err := anvilwallet.New(key.Wif(), t.TempDir(), hs, ps, broadcaster, client, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nw.Close)
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t),
		NonceProvider: &DevNonceProvider{}, ARCClient: client, HeaderTip: hs.Tip})
	if err := pg.enableBRC121(nw.Wallet(), spv.NewValidator(hs), t.TempDir(), slog.Default()); err != nil {
		t.Fatal(err)
	}
	pg.brc121.submit = func(ctx context.Context, p *brc121Payment, sweep bool) (*txrelay.ARCResponse, error) {
		return submitBRC121With(ctx, p, sweep, arc.send)
	}
	t.Cleanup(pg.closeBRC121)
	server, err := ec.PublicKeyFromString(pg.brc121.server)
	if err != nil || !server.IsEqual(key.PubKey()) {
		t.Fatalf("x-bsv-server must be the node wallet's identity key, got %q (%v)", pg.brc121.server, err)
	}
	return &realBRC121Node{pg: pg, nw: nw, arc: arc, payer: payer, server: server}
}

func (n *realBRC121Node) serve(h map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, brc121Path, nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	n.pg.Middleware(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })(w, req)
	return w
}

// spendable lists the change basket's outputs paying txid.
func (n *realBRC121Node) spendable(t *testing.T, txid string) []sdk.Output {
	t.Helper()
	res, err := n.nw.Wallet().ListOutputs(context.Background(), sdk.ListOutputsArgs{Basket: "default"}, "anvil")
	if err != nil {
		t.Fatal(err)
	}
	var outs []sdk.Output
	for _, o := range res.Outputs {
		if o.Outpoint.Txid.String() == txid {
			outs = append(outs, o)
		}
	}
	return outs
}

// TestBRC121RealWalletRecordsSpendablePayment: with the node's own wallet, a
// BRC-121 payment is recorded and listed in the change basket as spendable,
// its transaction reaches "broadcasted" once the wallet's background broadcast
// admits it locally and announces it to the mesh, and the wallet then spends it: it signs a transaction taking
// that output as its input, which go-sdk's interpreter verifies.
func TestBRC121RealWalletRecordsSpendablePayment(t *testing.T) {
	n := newRealBRC121Node(t)
	h := n.payer.pay(t, n.server, 100, time.Now(), brc121Pay{})
	w := n.serve(h)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
	p := &brc121Payment{}
	if err := p.readBRC121BEEF(h[headerBRC121Beef], 100); err != nil {
		t.Fatal(err)
	}
	txid := p.txid.String()
	outs := n.spendable(t, txid)
	if len(outs) != 1 || !outs[0].Spendable || outs[0].Satoshis != 100 || outs[0].Outpoint.Index != 0 {
		t.Fatalf("want the 100-sat output listed spendable in the change basket, got %+v", outs)
	}

	// The wallet's background broadcaster takes the transaction to BroadcastRaw,
	// which admits it to the local mempool and announces it to mesh peers.
	deadline := time.Now().Add(10 * time.Second)
	status := ""
	for time.Now().Before(deadline) {
		res, err := n.nw.Wallet().(brc121Wallet).ListTransactions(context.Background(), wdk.ListTransactionsArgs{TxIDs: []string{txid}, Limit: 1}, "anvil")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Transactions) == 1 {
			status = string(res.Transactions[0].Status)
			if status == "broadcasted" {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("payment status after the background broadcast: %q", status)
	if status != "broadcasted" {
		t.Fatalf("the payment status did not reach broadcasted: %q", status)
	}

	// Spend it: the wallet funds a 50-sat output from its change basket,
	// whose only output is the payment, and signs.
	dest, _ := ec.NewPrivateKey()
	addr, _ := bsvscript.NewAddressFromPublicKey(dest.PubKey(), true)
	lock, _ := p2pkh.Lock(addr)
	noSend, noRandom := true, false
	res, err := n.nw.Wallet().CreateAction(context.Background(), sdk.CreateActionArgs{
		Description: "spend a payment",
		Outputs:     []sdk.CreateActionOutput{{LockingScript: *lock, Satoshis: 50, OutputDescription: "spent payment"}},
		Options:     &sdk.CreateActionOptions{NoSend: &noSend, RandomizeOutputs: &noRandom},
	}, "anvil")
	if err != nil {
		t.Fatalf("the wallet could not spend the payment: %v", err)
	}
	spend, err := transaction.NewTransactionFromBEEF(res.Tx)
	if err != nil {
		t.Fatal(err)
	}
	spent := false
	for i, in := range spend.Inputs {
		if in.SourceTXID.String() != txid {
			continue
		}
		spent = true
		if err := runNonceScripts(spend, i, p.tx.Outputs[in.SourceTxOutIndex]); err != nil {
			t.Fatalf("the wallet's spend of the payment does not verify: %v", err)
		}
	}
	if !spent {
		t.Fatalf("the spend does not take the payment as an input")
	}

	// Presented again to a fresh replay record, as after a restart, the
	// payment is refused by the wallet's own record, before ARC.
	calls := n.arc.calls.Load()
	n.pg.replays = newPaymentReplaySet(time.Hour, 16, time.Now)
	again := n.serve(h)
	if again.Code != http.StatusPaymentRequired || codeOf(t, again) != codeBRC121Replayed || n.arc.calls.Load() != calls {
		t.Fatalf("a recorded payment presented again: want 402 %s before ARC, got %d %s", codeBRC121Replayed, again.Code, again.Body.String())
	}
}
