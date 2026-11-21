package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

func TestDirectPaymentCapacityTakenBeforeDecoding(t *testing.T) {
	previous := directPaymentSubmitSlots
	directPaymentSubmitSlots = make(chan struct{}, 1)
	directPaymentSubmitSlots <- struct{}{}
	t.Cleanup(func() { directPaymentSubmitSlots = previous })

	payee := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{}, ARCClient: txrelay.NewARCClient("http://127.0.0.1:1", ""),
	})
	_, err := pg.verifyDirectPayment(context.Background(), "not a transaction", []Payee{{
		Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100,
	}})
	var refusal *paymentRefusal
	if !errors.As(err, &refusal) || refusal.code != codeDirectPaymentBusy {
		t.Fatalf("a request past the concurrency cap reached payment decoding: %v", err)
	}
}

func TestFullReplaySetAnswers503WithoutOffer(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	srv.paymentGate.arcClient = txrelay.NewARCClient("http://127.0.0.1:1", "")
	srv.paymentGate.replays = newPaymentReplaySet(time.Hour, 1, time.Now)
	old := replayTxID(1)
	srv.paymentGate.replays.begin(old)
	srv.paymentGate.replays.end(old, true)
	ef := signedEFPaying(t, paidOut{testPayeeScript(t), 100})
	w := serveDirectPayment(srv, "/stats", ef)
	var body codedError
	if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != codePaymentReplayFull {
		t.Fatalf("full replay set: got %d %s, want 503 with %s", w.Code, w.Body.String(), codePaymentReplayFull)
	}
	if w.Header().Get(HeaderX402Challenge) != "" || w.Header().Get(headerBRC121Sats) != "" {
		t.Fatal("full replay set advertised another payment")
	}
	if srv.paymentGate.replays.begin(old) {
		t.Fatal("full replay set evicted the accepted payment")
	}
}

func TestSplitPayeesNeedDistinctOutputs(t *testing.T) {
	payee := testPayeeScript(t)
	srv := testServer(t)
	seedEnvelopeAt(t, srv.envelopeStore, "same-payee", `{"paid":true}`, time.Now().Unix(), &envelope.Monetization{
		Model: envelope.MonetizationSplit, PayeeLockingScriptHex: payee, PriceSats: 50,
	})
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
		Resolver: NewTopicMonetizationResolver(srv.envelopeStore), AllowSplit: true,
	})
	rebuildRoutes(srv)
	path := "/data?topic=same-payee"
	ch := getChallenge(t, srv, http.MethodGet, path)
	if len(ch.Payees) != 2 {
		t.Fatalf("split challenge has %d payees, want 2", len(ch.Payees))
	}
	w := getWithHeaders(srv, path, map[string]string{HeaderX402Proof: buildProof(t, ch, 100, payee)})
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("one output satisfied two payee requirements: got %d %s", w.Code, w.Body.String())
	}
}

func TestBRC121OfferDoesNotAdvertiseProofPath(t *testing.T) {
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
	})
	pg.brc121 = &brc121Gate{server: "server"}
	w := serveGate(pg, http.MethodGet, "/status", "", "")
	if w.Code != http.StatusPaymentRequired || w.Header().Get(headerBRC121Sats) != "100" {
		t.Fatalf("node-only request did not offer BRC-121: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get(HeaderX402Challenge) != "" {
		t.Fatal("BRC-121 offer also advertised the node-only proof path")
	}
}

func TestDisabledAppModelMakesNoPaymentOffer(t *testing.T) {
	srv := testServer(t)
	seedEnvelopeAt(t, srv.envelopeStore, "disabled", `{"paid":true}`, time.Now().Unix(), &envelope.Monetization{
		Model: envelope.MonetizationPassthrough, PayeeLockingScriptHex: appPayeeScript(), PriceSats: 50,
	})
	srv.paymentGate = NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
		Resolver: NewTopicMonetizationResolver(srv.envelopeStore), AllowPassthrough: false,
	})
	rebuildRoutes(srv)
	w := getWithHeaders(srv, "/data?topic=disabled", nil)
	if w.Code != http.StatusOK || w.Header().Get(HeaderX402Challenge) != "" || w.Header().Get(headerBRC121Sats) != "" {
		t.Fatalf("disabled app model offered a payment that cannot unlock content: %d %s", w.Code, w.Body.String())
	}
}

func TestARCResponseNamesSubmittedTransaction(t *testing.T) {
	submitted := chainhash.Hash(sha256.Sum256([]byte("submitted")))
	resp := &txrelay.ARCResponse{TxID: strings.Repeat("f", 64), Status: "SEEN_ON_NETWORK"}
	if err := checkARCAcceptance(resp, &submitted); err == nil {
		t.Fatal("accepted an ARC response naming a different transaction")
	}
}

func TestMinedARCResponseNeedsLocalMerkleProof(t *testing.T) {
	submitted := chainhash.Hash(sha256.Sum256([]byte("mined")))
	resp := &txrelay.ARCResponse{TxID: submitted.String(), Status: "MINED", BlockHeight: 800_000,
		BlockHash: "not-a-block-hash", MerklePath: "not-a-merkle-path"}
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
		HeaderTip: func() uint32 { return 800_000 },
	})
	if err := checkARCAcceptance(resp, &submitted); err != nil {
		t.Fatalf("valid submitted txid was rejected before finality: %v", err)
	}
	if err := pg.checkPaymentFinality(resp, &submitted); err == nil {
		t.Fatal("accepted MINED without a proof against the node's headers")
	}
}

func TestProofARCUsesSharedCapacity(t *testing.T) {
	previous := directPaymentSubmitSlots
	directPaymentSubmitSlots = make(chan struct{}, 1)
	directPaymentSubmitSlots <- struct{}{}
	t.Cleanup(func() { directPaymentSubmitSlots = previous })

	payee := testPayeeScript(t)
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 100, PayeeScriptHex: payee, NonceProvider: &DevNonceProvider{},
		RequireMempool: true, ARCClient: txrelay.NewARCClient("http://127.0.0.1:1", ""),
	})
	ch := gateChallenge(t, pg, "/status")
	w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, buildProof(t, ch, 100, payee))
	var body codedError
	if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Code != codeDirectPaymentBusy {
		t.Fatalf("a proof bypassed the shared ARC capacity: got %d %s", w.Code, w.Body.String())
	}
}

type blockingMintProvider struct {
	mu      sync.Mutex
	in      int
	peak    int
	started chan struct{}
	release chan struct{}
}

func (p *blockingMintProvider) MintNonce(ctx context.Context) (*NonceUTXO, error) {
	p.mu.Lock()
	p.in++
	if p.in > p.peak {
		p.peak = p.in
	}
	p.mu.Unlock()
	p.started <- struct{}{}
	select {
	case <-p.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	p.mu.Lock()
	p.in--
	p.mu.Unlock()
	h := chainhash.Hash(sha256.Sum256([]byte(time.Now().String())))
	return &NonceUTXO{TxID: h.String(), Vout: 0, Satoshis: 1, LockingScriptHex: "dev-mode-no-real-utxo"}, nil
}

func TestNonceMintConcurrencyIsBounded(t *testing.T) {
	const requests = 8
	provider := &blockingMintProvider{started: make(chan struct{}, requests), release: make(chan struct{})}
	pg := NewPaymentGate(PaymentGateConfig{
		PriceSats: 1, PayeeScriptHex: testPayeeScript(t), NonceProvider: provider,
		mintBudget: newMintBudget(requests, 60, time.Now),
	})
	done := make(chan struct{}, requests)
	for i := 0; i < requests; i++ {
		go func() {
			serveGate(pg, http.MethodGet, "/status", "", "")
			done <- struct{}{}
		}()
	}
	deadline := time.After(2 * time.Second)
	for i := 0; i < requests; i++ {
		select {
		case <-provider.started:
		case <-deadline:
			i = requests
		}
	}
	provider.mu.Lock()
	peak := provider.peak
	provider.mu.Unlock()
	close(provider.release)
	for i := 0; i < requests; i++ {
		<-done
	}
	if peak > 4 {
		t.Fatalf("%d wallet mints ran at once, want at most 4", peak)
	}
}

func TestNonceMintEndsWithRequestAndDeadline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{name: "request cancellation", cancel: true},
		{name: "operation deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := nonceMintTimeout
			nonceMintTimeout = 50 * time.Millisecond
			t.Cleanup(func() { nonceMintTimeout = previous })
			provider := &blockingMintProvider{started: make(chan struct{}, 1), release: make(chan struct{})}
			pg := NewPaymentGate(PaymentGateConfig{
				PriceSats: 1, PayeeScriptHex: testPayeeScript(t), NonceProvider: provider,
				mintBudget: newMintBudget(1, 60, time.Now),
			})
			ctx, cancel := context.WithCancel(context.Background())
			req := httptest.NewRequest(http.MethodGet, "/status", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				pg.Middleware(func(http.ResponseWriter, *http.Request) {})(w, req)
				close(done)
			}()
			<-provider.started
			if tc.cancel {
				cancel()
			} else {
				defer cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("nonce mint outlived its request or operation deadline")
			}
		})
	}
}

type optionRecordingWallet struct {
	sdk.Interface
	proto *sdk.ProtoWallet
	args  sdk.CreateActionArgs
}

func (w *optionRecordingWallet) GetPublicKey(ctx context.Context, args sdk.GetPublicKeyArgs, originator string) (*sdk.GetPublicKeyResult, error) {
	return w.proto.GetPublicKey(ctx, args, originator)
}

func (w *optionRecordingWallet) CreateAction(_ context.Context, args sdk.CreateActionArgs, _ string) (*sdk.CreateActionResult, error) {
	w.args = args
	return &sdk.CreateActionResult{Txid: chainhash.Hash(sha256.Sum256(args.Outputs[0].LockingScript))}, nil
}

func TestWalletNonceKeepsRequestedOutputAtVoutZero(t *testing.T) {
	root, _ := ec.NewPrivateKey()
	proto, err := sdk.NewProtoWallet(sdk.ProtoWalletArgs{Type: sdk.ProtoWalletArgsTypePrivateKey, PrivateKey: root})
	if err != nil {
		t.Fatal(err)
	}
	wallet := &optionRecordingWallet{proto: proto}
	if _, err := NewWalletNonceProvider(wallet).MintNonce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if wallet.args.Options == nil || wallet.args.Options.RandomizeOutputs == nil || *wallet.args.Options.RandomizeOutputs {
		t.Fatal("nonce creation did not disable wallet output randomization")
	}
}

func TestNonceOutputIndexFindsBothOutputOrders(t *testing.T) {
	nonceScript := bsvscript.Script{bsvscript.OpTRUE}
	changeScript := bsvscript.Script{bsvscript.OpFALSE}
	for _, nonceAt := range []int{0, 1} {
		tx := transaction.NewTransaction()
		outputs := []*transaction.TransactionOutput{
			{Satoshis: 1, LockingScript: &nonceScript},
			{Satoshis: 99, LockingScript: &changeScript},
		}
		if nonceAt == 1 {
			outputs[0], outputs[1] = outputs[1], outputs[0]
		}
		for _, out := range outputs {
			tx.AddOutput(out)
		}
		got, err := nonceOutputIndex(tx.Bytes(), nonceScript)
		if err != nil || got != nonceAt {
			t.Fatalf("nonce at output %d: got %d, %v", nonceAt, got, err)
		}
	}
}

func TestPaymentBodyTimeoutDoesNotOutliveChallenge(t *testing.T) {
	if paymentBodyLimits.Timeout > 60*time.Second {
		t.Fatalf("a payment body may hold capacity for %v, past the default 60s challenge lifetime", paymentBodyLimits.Timeout)
	}
}

func TestPaymentBodyShareReleasedAtChallengeExpiry(t *testing.T) {
	previousLimits := paymentBodyLimits
	paymentBodyLimits.Grace = time.Second
	paymentBodyLimits.Timeout = 5 * time.Second
	t.Cleanup(func() { paymentBodyLimits = previousLimits })
	previousShares := paymentBodyShares
	paymentBodyShares = newBodyShares(1)
	t.Cleanup(func() { paymentBodyShares = previousShares })
	previousReads := paymentBodyReads
	paymentBodyReads = bodyread.NewPermits(1)
	t.Cleanup(func() { paymentBodyReads = previousReads })

	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close() })
	req := httptest.NewRequest(http.MethodPost, "/data", reader)
	req.RemoteAddr = "192.0.2.1:1234"
	pg := testGate(t, 100)
	done := make(chan error, 1)
	go func() {
		_, err := pg.readPaymentBodyUntil(httptest.NewRecorder(), req, time.Now().Add(50*time.Millisecond))
		done <- err
	}()
	eventually(t, time.Second, func() bool { return paymentBodyShares.holding("192.0.2.1") == 1 })
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("body read survived its challenge expiry")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("body slot survived its challenge expiry")
	}
	if paymentBodyShares.holding("192.0.2.1") != 0 || paymentBodyReads.InUse() != 0 {
		t.Fatal("challenge expiry did not release body capacity")
	}
}
