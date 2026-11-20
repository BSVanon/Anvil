package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// genesisBlockTxID is the txid of the genesis block's only transaction, whose
// one output pays Satoshi's key, not any key a test holds.
const genesisBlockTxID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

// spendOfClaimedOutput builds a transaction that spends output 0 of
// srcTxIDHex, paying paySats to payeeScriptHex. Its Extended Format input
// carries a source output the builder made up: claimedSats locked to a fresh
// key, which also signs the spend. The signature is valid against that made-up
// output and nothing else.
func spendOfClaimedOutput(t *testing.T, srcTxIDHex string, claimedSats, paySats uint64, payeeScriptHex string) *transaction.Transaction {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	addr, err := bsvscript.NewAddressFromPublicKey(key.PubKey(), true)
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}
	lock, err := p2pkh.Lock(addr)
	if err != nil {
		t.Fatalf("build lock script: %v", err)
	}
	src, err := chainhash.NewHashFromHex(srcTxIDHex)
	if err != nil {
		t.Fatalf("parse source txid: %v", err)
	}
	tx := transaction.NewTransaction()
	in := &transaction.TransactionInput{SourceTXID: src, SourceTxOutIndex: 0, SequenceNumber: 0xffffffff}
	in.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: claimedSats, LockingScript: lock})
	tx.AddInput(in)
	payee, err := hex.DecodeString(payeeScriptHex)
	if err != nil {
		t.Fatalf("decode payee script: %v", err)
	}
	ls := bsvscript.Script(payee)
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: paySats, LockingScript: &ls})
	unlock, err := p2pkh.Unlock(key, nil)
	if err != nil {
		t.Fatalf("create unlock template: %v", err)
	}
	tx.Inputs[0].UnlockingScriptTemplate = unlock
	if err := tx.Sign(); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tx
}

// serveDirectPayment sends GET path with value as X-Bsv-Payment.
func serveDirectPayment(srv *Server, path, value string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "localhost"
	req.Header.Set(HeaderBSVPayment, value)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// requirePaymentCode fails unless w is a 402 carrying the error code want.
func requirePaymentCode(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("got %d %s, want 402 with code %s", w.Code, w.Body.String(), want)
	}
	var body codedError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Code != want {
		t.Fatalf("got body %s, want code %s", w.Body.String(), want)
	}
}

// Each spend below has a valid signature against the source output it
// carries, and that output is a claim nothing checks without ARC. A node at
// 100 sats with no ARC client used to answer each of them 200.
func TestDirectPaymentRefusedWithoutARCForClaimedSourceOutputs(t *testing.T) {
	payee := testPayeeScript(t)
	cases := []struct {
		name string
		tx   *transaction.Transaction
	}{
		{"a parent that never existed", spendOfClaimedOutput(t, strings.Repeat("ab", 32), 1000, 100, payee)},
		{"1 sat in, 1,000,000 sats out", spendOfClaimedOutput(t, strings.Repeat("cd", 32), 1, 1_000_000, payee)},
		{"the genesis coinbase output, claimed as the spender's", spendOfClaimedOutput(t, genesisBlockTxID, 5_000_000_000, 100, payee)},
	}
	srv := testServerWithPaymentGate(t, 100) // no ARC client
	for _, tc := range cases {
		ef, err := tc.tx.EFHex()
		if err != nil {
			t.Fatalf("%s: serialize extended format: %v", tc.name, err)
		}
		w := serveDirectPayment(srv, "/stats", ef)
		t.Logf("%s: %d", tc.name, w.Code)
		requirePaymentCode(t, w, codeDirectPaymentUnavailable)
	}
}

// TestDirectPaymentAtomicBEEFIsNotParsed pins a documented limit: the direct
// path parses a raw or Extended Format transaction only, so an honest payment
// sent as Atomic BEEF (BRC-95) is refused with 402 before ARC is asked.
func TestDirectPaymentAtomicBEEFIsNotParsed(t *testing.T) {
	srv := testServerWithPaymentGate(t, 100)
	srv.paymentGate.arcClient = mockARCServer(t)
	tx := buildSignedDirectPaymentTx(t, testPayeeScript(t), 100)
	beef, err := tx.AtomicBEEF(true)
	if err != nil {
		t.Fatalf("AtomicBEEF: %v", err)
	}
	w := serveDirectPayment(srv, "/stats", hex.EncodeToString(beef))
	if w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "invalid transaction in payment header") {
		t.Fatalf("an Atomic BEEF X-Bsv-Payment: got %d %s, want 402 from the transaction parse", w.Code, w.Body.String())
	}
}
