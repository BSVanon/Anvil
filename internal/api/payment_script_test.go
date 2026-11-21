package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/errs"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

// keyNonceProvider mints P2PKH nonces locked to key at fresh random outpoints,
// the way WalletNonceProvider locks them to a node wallet key. Tests hold the
// key, so they can sign a valid nonce spend.
type keyNonceProvider struct {
	key *ec.PrivateKey
}

// noncesCostNothing exempts the provider from the process-wide mint budget
// (payment_budget.go), which the tests of this package would otherwise share
// and exhaust; payment_budget_test.go tests the budget.
func (*keyNonceProvider) noncesCostNothing() {}

func (p *keyNonceProvider) MintNonce(context.Context) (*NonceUTXO, error) {
	addr, err := bsvscript.NewAddressFromPublicKey(p.key.PubKey(), true)
	if err != nil {
		return nil, err
	}
	lock, err := p2pkh.Lock(addr)
	if err != nil {
		return nil, err
	}
	var txid [32]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return nil, err
	}
	return &NonceUTXO{TxID: hex.EncodeToString(txid[:]), Vout: 0, Satoshis: 1, LockingScriptHex: hex.EncodeToString(*lock)}, nil
}

// scriptBomb is the reviewer's slow unlocking script: a 1000-byte push, doubled
// with OP_DUP OP_CAT, then hashed again and again with OP_DUP OP_SHA256 OP_DROP.
func scriptBomb(doublings, hashes int) *bsvscript.Script {
	s := &bsvscript.Script{}
	_ = s.AppendPushData(bytes.Repeat([]byte{0x42}, 1000))
	for i := 0; i < doublings; i++ {
		_ = s.AppendOpcodes(bsvscript.OpDUP, bsvscript.OpCAT)
	}
	for i := 0; i < hashes; i++ {
		_ = s.AppendOpcodes(bsvscript.OpDUP, bsvscript.OpSHA256, bsvscript.OpDROP)
	}
	return s
}

// fourKBBomb is the 4 KB shape the reviewer timed at 13.4 s: a 16 MB element
// hashed 1021 times, 4094 bytes in all.
func fourKBBomb() *bsvscript.Script { return scriptBomb(14, 1021) }

// nonceSpend builds a transaction whose input 0 spends nonce and whose output
// pays payeeSats to payeeScriptHex. With unlock nil it signs input 0 with key;
// otherwise unlock is the input's unlocking script.
func nonceSpend(t *testing.T, nonce *NonceUTXO, key *ec.PrivateKey, version uint32, payeeSats uint64, payeeScriptHex string, unlock *bsvscript.Script) *transaction.Transaction {
	t.Helper()
	nonceTxID, err := chainhash.NewHashFromHex(nonce.TxID)
	if err != nil {
		t.Fatalf("nonce txid: %v", err)
	}
	lock, err := bsvscript.NewFromHex(nonce.LockingScriptHex)
	if err != nil {
		t.Fatalf("nonce lock: %v", err)
	}
	tx := transaction.NewTransaction()
	tx.Version = version
	in := &transaction.TransactionInput{SourceTXID: nonceTxID, SourceTxOutIndex: uint32(nonce.Vout), SequenceNumber: 0xffffffff}
	in.SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: uint64(nonce.Satoshis), LockingScript: lock})
	tx.AddInput(in)
	payee, err := bsvscript.NewFromHex(payeeScriptHex)
	if err != nil {
		t.Fatalf("payee script: %v", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: payeeSats, LockingScript: payee})
	if unlock != nil {
		tx.Inputs[0].UnlockingScript = unlock
		return tx
	}
	tmpl, err := p2pkh.Unlock(key, nil)
	if err != nil {
		t.Fatalf("unlock template: %v", err)
	}
	tx.Inputs[0].UnlockingScriptTemplate = tmpl
	if err := tx.Sign(); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tx
}

// proofForTx encodes tx as an X402-Proof header value for challenge ch.
func proofForTx(t *testing.T, ch *X402Challenge, tx *transaction.Transaction) string {
	t.Helper()
	challengeJSON, err := json.Marshal(ch)
	if err != nil {
		t.Fatalf("marshal challenge: %v", err)
	}
	proofJSON, err := json.Marshal(X402Proof{
		V:               1,
		Scheme:          "bsv-tx-v1",
		ChallengeSHA256: sha256Hex(challengeJSON),
		Request: ProofRequest{
			Method: ch.Method, Path: ch.Path, Query: ch.Query,
			ReqHeadersSHA256: ch.ReqHeadersSHA256, ReqBodySHA256: ch.ReqBodySHA256,
		},
		Payment: ProofPayment{TxID: tx.TxID().String(), RawTxB64: base64.StdEncoding.EncodeToString(tx.Bytes())},
	})
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	return base64Url(proofJSON)
}

// serveGate runs one request through pg's middleware in front of a 200 handler.
func serveGate(pg *PaymentGate, method, target, header, value string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "localhost"
	if header != "" {
		req.Header.Set(header, value)
	}
	w := httptest.NewRecorder()
	pg.Middleware(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(w, req)
	return w
}

// gateChallenge requests target without payment and returns the 402 challenge.
func gateChallenge(t *testing.T, pg *PaymentGate, target string) *X402Challenge {
	t.Helper()
	w := serveGate(pg, http.MethodGet, target, "", "")
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("challenge: got %d: %s", w.Code, w.Body.String())
	}
	var ch X402Challenge
	if err := json.NewDecoder(w.Body).Decode(&ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return &ch
}

// keyNonceGate is a gate that charges 100 sats and mints real P2PKH nonces.
func keyNonceGate(t *testing.T) (*PaymentGate, *ec.PrivateKey) {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return NewPaymentGate(PaymentGateConfig{PriceSats: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &keyNonceProvider{key: key}}), key
}

func TestNonceScriptFlags(t *testing.T) {
	unmined := scriptflag.MainNetActivationHeights.BlockValidationFlags(math.MaxUint32, math.MaxUint32)
	if want := unmined &^ (scriptflag.Chronicle | scriptflag.UTXOAfterChronicle); nonceScriptFlags != want {
		t.Fatalf("flags %b, want spv.Verify's unmined flags %b without the Chronicle bits", nonceScriptFlags, want)
	}
	for _, tc := range []struct {
		name string
		flag scriptflag.Flag
		want bool
	}{
		{"VerifySigPushOnly", scriptflag.VerifySigPushOnly, true},
		{"VerifyLowS", scriptflag.VerifyLowS, true},
		{"VerifyNullFail", scriptflag.VerifyNullFail, true},
		{"VerifyDERSignatures", scriptflag.VerifyDERSignatures, true},
		{"VerifyStrictEncoding", scriptflag.VerifyStrictEncoding, true},
		{"EnableSighashForkID", scriptflag.EnableSighashForkID, true}, // set by WithForkID before
		{"UTXOAfterGenesis", scriptflag.UTXOAfterGenesis, true},       // set by WithAfterGenesis before
		{"Genesis", scriptflag.Genesis, true},
		{"UTXOAfterChronicle", scriptflag.UTXOAfterChronicle, false},
		{"Chronicle", scriptflag.Chronicle, false},
	} {
		if got := nonceScriptFlags.HasFlag(tc.flag); got != tc.want {
			t.Errorf("%s set = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The interpreter itself refuses a script that is not push-only, for every
// transaction version, before running it.
func TestNonceScriptsRefuseNonPushOnly(t *testing.T) {
	previous := nonceScriptTimeout
	nonceScriptTimeout = 5 * time.Second // long enough that running the bomb shows
	t.Cleanup(func() { nonceScriptTimeout = previous })
	nonce, _ := (&keyNonceProvider{key: mustKey(t)}).MintNonce(t.Context())
	lock, _ := bsvscript.NewFromHex(nonce.LockingScriptHex)
	for _, version := range []uint32{1, 2} {
		tx := nonceSpend(t, nonce, nil, version, 500, testPayeeScript(t), fourKBBomb())
		start := time.Now()
		err := runNonceScripts(tx, 0, &transaction.TransactionOutput{LockingScript: lock, Satoshis: 1})
		elapsed := time.Since(start)
		if !errs.IsErrorCode(err, errs.ErrNotPushOnly) {
			t.Fatalf("version %d: err = %v, want ErrNotPushOnly", version, err)
		}
		if elapsed > 100*time.Millisecond {
			t.Fatalf("version %d: refused after %s, want under 100ms", version, elapsed)
		}
		t.Logf("version %d: 4094-byte bomb refused in %s", version, elapsed)
	}
}

// A slow script stops at nonceScriptTimeout. The slow part is in the locking
// script, since the unlocking script must be push-only.
func TestNonceScriptsStopAtTimeout(t *testing.T) {
	previous := nonceScriptTimeout
	nonceScriptTimeout = 100 * time.Millisecond
	t.Cleanup(func() { nonceScriptTimeout = previous })
	slow := scriptBomb(14, 300)
	slowLock := bsvscript.Script((*slow)[1003:]) // the opcodes after the 1000-byte push
	seed := &bsvscript.Script{}
	_ = seed.AppendPushData(bytes.Repeat([]byte{0x42}, 1000))
	nonce, _ := (&keyNonceProvider{key: mustKey(t)}).MintNonce(t.Context())
	tx := nonceSpend(t, nonce, nil, 1, 500, testPayeeScript(t), seed)
	start := time.Now()
	err := runNonceScripts(tx, 0, &transaction.TransactionOutput{LockingScript: &slowLock, Satoshis: 1})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || !errs.IsErrorCode(err, errs.ErrExecutionCancelled) {
		t.Fatalf("err = %v, want the interpreter cancelled by its deadline", err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("stopped after %s, want about the 100ms deadline", elapsed)
	}
	t.Logf("slow script stopped after %s with a 100ms deadline", elapsed)
}

// Anything that cannot be a P2PKH spend of the nonce is refused before the
// interpreter, with errNonceUnlockingNotP2PKH.
func TestNonceUnlockingMustBeP2PKHShaped(t *testing.T) {
	key := mustKey(t)
	nonce, _ := (&keyNonceProvider{key: key}).MintNonce(t.Context())
	sig := bytes.Repeat([]byte{0x30}, 71)
	pub := key.PubKey().Compressed()
	pushes := func(items ...[]byte) *bsvscript.Script {
		s := &bsvscript.Script{}
		for _, item := range items {
			_ = s.AppendPushData(item)
		}
		return s
	}
	withOps := func(s *bsvscript.Script, ops ...byte) *bsvscript.Script { _ = s.AppendOpcodes(ops...); return s }
	cases := []struct {
		name   string
		unlock *bsvscript.Script
		lock   string
	}{
		{"4 KB bomb", fourKBBomb(), ""},
		{"push-only but oversized", pushes(sig, pub, bytes.Repeat([]byte{1}, 60)), ""},
		{"not push-only", withOps(pushes(sig), bsvscript.OpDUP), ""},
		{"three pushes", pushes([]byte{1}, pub, pub), ""},
		{"one push", pushes(sig), ""},
		{"small-integer opcode", withOps(pushes(sig), bsvscript.Op1), ""},
		{"74-byte signature", pushes(bytes.Repeat([]byte{0x30}, 74), pub), ""},
		{"32-byte public key", pushes(sig, pub[:32]), ""},
		{"truncated push", &bsvscript.Script{0x00, 0x48, 0x30, 0x45}, ""},
		{"nonce lock not P2PKH", pushes(sig, pub), "51"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := *nonce
			if tc.lock != "" {
				n.LockingScriptHex = tc.lock
			}
			tx := nonceSpend(t, &n, nil, 1, 500, testPayeeScript(t), tc.unlock)
			start := time.Now()
			err := verifyNonceInputSignature(tx, &n)
			elapsed := time.Since(start)
			if !errors.Is(err, errNonceUnlockingNotP2PKH) {
				t.Fatalf("err = %v, want errNonceUnlockingNotP2PKH", err)
			}
			if elapsed > 100*time.Millisecond {
				t.Fatalf("refused after %s, want under 100ms", elapsed)
			}
		})
	}
	// A signed spend has the shape and passes the interpreter.
	if err := verifyNonceInputSignature(nonceSpend(t, nonce, key, 2, 500, testPayeeScript(t), nil), nonce); err != nil {
		t.Fatalf("signed version-2 spend: %v", err)
	}
}

// Through the HTTP gate: a proof whose nonce input carries the 4 KB bomb is
// refused within the bound, and a signed nonce spend is accepted.
func TestX402NonceScriptThroughGate(t *testing.T) {
	pg, key := keyNonceGate(t)
	ch := gateChallenge(t, pg, "/status")
	bomb := proofForTx(t, ch, nonceSpend(t, ch.NonceUTXO, nil, 2, 200, testPayeeScript(t), fourKBBomb()))
	start := time.Now()
	w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, bomb)
	elapsed := time.Since(start)
	if w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "nonce input signature invalid") {
		t.Fatalf("bomb: got %d %s, want 402 from the nonce check", w.Code, w.Body.String())
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("bomb refused after %s, want under 100ms", elapsed)
	}
	t.Logf("4094-byte bomb proof refused in %s", elapsed)

	ch = gateChallenge(t, pg, "/status")
	good := proofForTx(t, ch, nonceSpend(t, ch.NonceUTXO, key, 1, 200, testPayeeScript(t), nil))
	if w := serveGate(pg, http.MethodGet, "/status", HeaderX402Proof, good); w.Code != http.StatusOK || w.Header().Get(HeaderX402Receipt) == "" {
		t.Fatalf("signed nonce spend: got %d %s, want 200 with a receipt", w.Code, w.Body.String())
	}
}

func mustKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return key
}
