package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/spv"
	"github.com/BSVanon/Anvil/internal/txrelay"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/wdk"
	p2pchainhash "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
)

// fakeBRC121Wallet stands in for the node wallet. Its keys are a go-sdk
// KeyDeriver's, and InternalizeAction checks a wallet payment as the toolbox
// does (validate_internalize_action_args.go:77-95, keyed by the remittance's
// bytes in base64 as mapping_internalize_action.go:46-63 keys it), refuses an
// Atomic BEEF holding unrelated entries as go-sdk's NewBeefFromAtomicBytes
// does, and answers a transaction it already holds as accepted, a merge,
// as the toolbox does (internalize.go:156).
type fakeBRC121Wallet struct {
	root           *ec.PrivateKey
	kd             *sdk.KeyDeriver
	mu             sync.Mutex
	held           map[string]bool
	internalizes   int
	merges         int
	internalizeErr error
	blockSender    *ec.PublicKey // derivations for this sender wait on release
	started        chan struct{}
	release        chan struct{}
}

func newFakeBRC121Wallet() *fakeBRC121Wallet {
	root, _ := ec.NewPrivateKey()
	return &fakeBRC121Wallet{root: root, kd: sdk.NewKeyDeriver(root), held: map[string]bool{}}
}

func (f *fakeBRC121Wallet) GetPublicKey(ctx context.Context, args sdk.GetPublicKeyArgs, _ string) (*sdk.GetPublicKeyResult, error) {
	if args.IdentityKey {
		return &sdk.GetPublicKeyResult{PublicKey: f.root.PubKey()}, nil
	}
	if f.blockSender != nil && args.Counterparty.Counterparty != nil && args.Counterparty.Counterparty.IsEqual(f.blockSender) {
		f.started <- struct{}{}
		select {
		case <-f.release:
		case <-ctx.Done():
		}
	}
	pub, err := f.kd.DerivePublicKey(args.ProtocolID, args.KeyID, args.Counterparty, args.ForSelf != nil && *args.ForSelf)
	if err != nil {
		return nil, err
	}
	return &sdk.GetPublicKeyResult{PublicKey: pub}, nil
}

func (f *fakeBRC121Wallet) InternalizeAction(_ context.Context, args sdk.InternalizeActionArgs, _ string) (*sdk.InternalizeActionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.internalizes++
	if f.internalizeErr != nil {
		return nil, f.internalizeErr
	}
	beef, txid, err := transaction.NewBeefFromAtomicBytes(args.Tx)
	if err != nil {
		return nil, err
	}
	tx := beef.FindAtomicTransactionByHash(txid)
	if tx == nil {
		return nil, errors.New("the atomic BEEF holds no subject")
	}
	for _, o := range args.Outputs {
		pr := o.PaymentRemittance
		keyID := base64.StdEncoding.EncodeToString(pr.DerivationPrefix) + " " + base64.StdEncoding.EncodeToString(pr.DerivationSuffix)
		priv, err := f.kd.DerivePrivateKey(brc121Protocol, keyID, sdk.Counterparty{Type: sdk.CounterpartyTypeOther, Counterparty: pr.SenderIdentityKey})
		if err != nil {
			return nil, err
		}
		addr, _ := bsvscript.NewAddressFromPublicKey(priv.PubKey(), true)
		want, _ := p2pkh.Lock(addr)
		if int(o.OutputIndex) >= len(tx.Outputs) || tx.Outputs[o.OutputIndex].LockingScript.String() != want.String() {
			return nil, errors.New("locking script mismatch")
		}
	}
	if f.held[txid.String()] {
		f.merges++
	}
	f.held[txid.String()] = true
	return &sdk.InternalizeActionResult{Accepted: true}, nil
}

func (f *fakeBRC121Wallet) ListTransactions(_ context.Context, args wdk.ListTransactionsArgs, _ string) (*wdk.ListTransactionsResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	res := &wdk.ListTransactionsResult{}
	for _, id := range args.TxIDs {
		if f.held[id] {
			res.TotalTransactions++
		}
	}
	return res, nil
}

func (f *fakeBRC121Wallet) recorded() (internalizes, held int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.internalizes, len(f.held)
}

// brc121ARC is a mock ARC that counts its submits and answers each with
// status (HTTP 200), or with httpCode when set, or not at all until hold is
// closed.
type brc121ARC struct {
	calls    atomic.Int32
	mu       sync.Mutex
	status   string
	httpCode int
	hold     chan struct{}
}

func newBRC121ARC(t *testing.T) (*brc121ARC, *txrelay.ARCClient) {
	t.Helper()
	a := &brc121ARC{status: "SEEN_ON_NETWORK"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.calls.Add(1)
		a.mu.Lock()
		status, code, hold := a.status, a.httpCode, a.hold
		a.mu.Unlock()
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		if code != 0 {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"title":"refused"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(txrelay.ARCResponse{TxID: "mock", Status: status})
	}))
	t.Cleanup(srv.Close)
	return a, txrelay.NewARCClient(srv.URL, "")
}

func (a *brc121ARC) answer(status string, httpCode int) {
	a.mu.Lock()
	a.status, a.httpCode = status, httpCode
	a.mu.Unlock()
}

// brc121HeaderStore is a header store whose height 1 is the one-transaction
// block mining source.
func brc121HeaderStore(t *testing.T, source *transaction.Transaction) *headers.Store {
	t.Helper()
	hs, err := headers.NewTestStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hs.Close() })
	prev, _ := hs.HashAtHeight(0)
	root, _ := p2pchainhash.NewHashFromStr(source.TxID().String())
	if err := hs.AddHeaders(1, []*wire.BlockHeader{wire.NewBlockHeader(1, prev, root, 0x1d00ffff, 1)}); err != nil {
		t.Fatal(err)
	}
	return hs
}

// brc121Payer pays as the reference client does (402-pay client.ts:41-105),
// with go-sdk on the sender's side: an 8-byte random nonce in base64, the
// time in milliseconds, the key derived under BRC-29 for the server with the
// key ID "<nonce> <base64(time)>", P2PKH to it at output 0. Its inputs spend
// outputs of source, a transaction mined in a block of its own at height 1.
type brc121Payer struct {
	identity *ec.PrivateKey
	funding  *ec.PrivateKey
	source   *transaction.Transaction
	next     int
}

func newBRC121Payer() *brc121Payer {
	identity, _ := ec.NewPrivateKey()
	funding, _ := ec.NewPrivateKey()
	addr, _ := bsvscript.NewAddressFromPublicKey(funding.PubKey(), true)
	lock, _ := p2pkh.Lock(addr)
	source := transaction.NewTransaction()
	for i := 0; i < 64; i++ {
		source.AddOutput(&transaction.TransactionOutput{Satoshis: 10_000, LockingScript: lock})
	}
	yes := true
	source.MerklePath = transaction.NewMerklePath(1, [][]*transaction.PathElement{{{Offset: 0, Hash: source.TxID(), Txid: &yes}}})
	return &brc121Payer{identity: identity, funding: funding, source: source}
}

// brc121Pay says how to build one payment; the zero value is the reference
// client's payment.
type brc121Pay struct {
	payTo     *ec.PublicKey // pay this key instead of the derived one
	inputs    int           // inputs to spend, 1 when 0
	wrongSig  bool          // sign with a key the spent outputs do not name
	plain     bool          // send a V2 BEEF, not an Atomic BEEF
	unrelated bool          // add a transaction outside the payment's ancestry
}

// pay returns the five headers of a payment of sats to server at now.
func (p *brc121Payer) pay(t *testing.T, server *ec.PublicKey, sats uint64, now time.Time, o brc121Pay) map[string]string {
	t.Helper()
	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	keyID := nonce + " " + base64.StdEncoding.EncodeToString([]byte(ts))
	derived, err := sdk.NewKeyDeriver(p.identity).DerivePublicKey(
		sdk.Protocol{SecurityLevel: 2, Protocol: "3241645161d8"}, keyID,
		sdk.Counterparty{Type: sdk.CounterpartyTypeOther, Counterparty: server}, false)
	if err != nil {
		t.Fatal(err)
	}
	if o.payTo != nil {
		derived = o.payTo
	}
	addr, _ := bsvscript.NewAddressFromPublicKey(derived, true)
	lock, _ := p2pkh.Lock(addr)
	tx := transaction.NewTransaction()
	n := o.inputs
	if n == 0 {
		n = 1
	}
	for i := 0; i < n; i++ {
		tx.AddInput(&transaction.TransactionInput{SourceTXID: p.source.TxID(), SourceTxOutIndex: uint32(p.next),
			SequenceNumber: 0xffffffff, SourceTransaction: p.source})
		p.next++
	}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: lock})
	signer := p.funding
	if o.wrongSig {
		signer, _ = ec.NewPrivateKey()
	}
	for i := range tx.Inputs {
		unlock, _ := p2pkh.Unlock(signer, nil)
		tx.Inputs[i].UnlockingScriptTemplate = unlock
	}
	if err := tx.Sign(); err != nil {
		t.Fatal(err)
	}
	beef, err := transaction.NewBeefFromTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := beef.AtomicBytes(tx.TxID())
	if err != nil {
		t.Fatal(err)
	}
	if o.unrelated {
		other := transaction.NewTransaction()
		other.AddInput(&transaction.TransactionInput{SourceTXID: p.source.TxID(), SourceTxOutIndex: uint32(p.next), SequenceNumber: 0xffffffff, SourceTransaction: p.source})
		p.next++
		other.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: lock})
		if _, err := beef.MergeTransaction(other); err != nil {
			t.Fatal(err)
		}
		whole, err := beef.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		raw = append(append([]byte{}, raw[:36]...), whole...)
	}
	if o.plain {
		if raw, err = beef.Bytes(); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]string{
		headerBRC121Beef:   base64.StdEncoding.EncodeToString(raw),
		headerBRC121Sender: p.identity.PubKey().ToDERHex(),
		headerBRC121Nonce:  nonce,
		headerBRC121Time:   ts,
		headerBRC121Vout:   "0",
	}
}

// brc121Fix is a payment gate that charges price and takes BRC-121, with a
// fake node wallet, a mock ARC, its own header store and a fixed clock.
type brc121Fix struct {
	pg     *PaymentGate
	wallet *fakeBRC121Wallet
	arc    *brc121ARC
	payer  *brc121Payer
	now    time.Time
	dir    string
}

func newBRC121Fix(t *testing.T, price int) *brc121Fix {
	t.Helper()
	payer := newBRC121Payer()
	hs := brc121HeaderStore(t, payer.source)
	arc, client := newBRC121ARC(t)
	pg := NewPaymentGate(PaymentGateConfig{PriceSats: price, PayeeScriptHex: testPayeeScript(t),
		NonceProvider: &DevNonceProvider{}, ARCClient: client, HeaderTip: hs.Tip})
	f := &brc121Fix{pg: pg, wallet: newFakeBRC121Wallet(), arc: arc, payer: payer, now: time.Now(), dir: t.TempDir()}
	if err := pg.startBRC121(f.wallet, spv.NewValidator(hs), f.dir, slog.Default()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pg.closeBRC121)
	pg.brc121.now = func() time.Time { return f.now }
	return f
}

func (f *brc121Fix) server() *ec.PublicKey { return f.wallet.root.PubKey() }

// payment is a payment of sats built at the fixture's clock.
func (f *brc121Fix) payment(t *testing.T, sats uint64, o brc121Pay) map[string]string {
	return f.payer.pay(t, f.server(), sats, f.now, o)
}

// serve sends GET path with headers from addr through the gate; the handler
// behind it answers 200 with the node coverage the request carries.
func (f *brc121Fix) serve(path, addr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = addr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.pg.Middleware(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(verifiedPaymentKey{}).(*verifiedPayment)
		cov := uint64(0)
		if p != nil {
			cov = p.nodeCoverage
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("node-coverage=" + strconv.FormatUint(cov, 10)))
	})(w, req)
	return w
}

// codeOf is a coded refusal's code.
func codeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Code
}

func withHeader(h map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(h)+1)
	for a, b := range h {
		out[a] = b
	}
	if v == "" {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}
