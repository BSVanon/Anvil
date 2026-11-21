package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// One replay set serves both payment paths: a transaction accepted on either
// path cannot pay again on either (payment_replay.go).

// proofCarrying is buildProof (payment_test.go) for a transaction the caller
// built: an X402-Proof answering ch whose payment is txBytes.
func proofCarrying(t *testing.T, ch *X402Challenge, txBytes []byte) string {
	t.Helper()
	tx, err := transaction.NewTransactionFromBytes(txBytes)
	if err != nil {
		t.Fatalf("parse transaction: %v", err)
	}
	challengeJSON, _ := json.Marshal(ch)
	proof := X402Proof{
		V: 1, Scheme: "bsv-tx-v1", ChallengeSHA256: sha256Hex(challengeJSON),
		Request: ProofRequest{Method: ch.Method, Path: ch.Path, Query: ch.Query,
			ReqHeadersSHA256: ch.ReqHeadersSHA256, ReqBodySHA256: ch.ReqBodySHA256},
		Payment: ProofPayment{TxID: tx.TxID().String(), RawTxB64: base64.StdEncoding.EncodeToString(txBytes)},
	}
	proofJSON, _ := json.Marshal(proof)
	return base64Url(proofJSON)
}

// replayPathsServer is a node charging 100 sats with a mock ARC, and a signed
// Extended Format payment of 100 to the node, as hex and as bytes.
func replayPathsServer(t *testing.T) (*Server, string, []byte) {
	t.Helper()
	srv := testServerWithPaymentGate(t, 100)
	srv.paymentGate.arcClient = mockARCServer(t)
	ef := signedEFPaying(t, paidOut{testPayeeScript(t), 100})
	b, err := hex.DecodeString(ef)
	if err != nil {
		t.Fatalf("decode payment: %v", err)
	}
	return srv, ef, b
}

// TestProofTransactionCannotPayAgainAsDirectPayment: a transaction an
// X402-Proof paid with is refused as an X-Bsv-Payment.
func TestProofTransactionCannotPayAgainAsDirectPayment(t *testing.T) {
	srv, ef, efBytes := replayPathsServer(t)
	ch := getChallenge(t, srv, http.MethodGet, "/stats")
	if w := getWithHeaders(srv, "/stats", map[string]string{HeaderX402Proof: proofCarrying(t, ch, efBytes)}); w.Code != http.StatusOK {
		t.Fatalf("the proof's first use: got %d %s, want 200", w.Code, w.Body.String())
	}
	requirePaymentCode(t, serveDirectPayment(srv, "/stats", ef), codePaymentReplayed)
}

// TestDirectPaymentTransactionCannotPayAgainAsProof: a transaction accepted
// as an X-Bsv-Payment is refused when an X402-Proof carries it.
func TestDirectPaymentTransactionCannotPayAgainAsProof(t *testing.T) {
	srv, ef, efBytes := replayPathsServer(t)
	if w := serveDirectPayment(srv, "/stats", ef); w.Code != http.StatusOK {
		t.Fatalf("the direct payment's first use: got %d %s, want 200", w.Code, w.Body.String())
	}
	ch := getChallenge(t, srv, http.MethodGet, "/stats")
	requirePaymentCode(t, getWithHeaders(srv, "/stats", map[string]string{HeaderX402Proof: proofCarrying(t, ch, efBytes)}), codePaymentReplayed)
}

// TestProofTransactionCannotPayTwoChallenges: one transaction can answer two
// challenges when it spends both nonces, or when, as here, the nonces are not
// real; it pays for the first request only.
func TestProofTransactionCannotPayTwoChallenges(t *testing.T) {
	srv, _, efBytes := replayPathsServer(t)
	first := getChallenge(t, srv, http.MethodGet, "/stats")
	second := getChallenge(t, srv, http.MethodGet, "/stats")
	if w := getWithHeaders(srv, "/stats", map[string]string{HeaderX402Proof: proofCarrying(t, first, efBytes)}); w.Code != http.StatusOK {
		t.Fatalf("the first challenge: got %d %s, want 200", w.Code, w.Body.String())
	}
	requirePaymentCode(t, getWithHeaders(srv, "/stats", map[string]string{HeaderX402Proof: proofCarrying(t, second, efBytes)}), codePaymentReplayed)
}
