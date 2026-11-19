package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/script/interpreter/scriptflag"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// Bounds on the work one x402 payment can make the node do: the size of the
// payment header, the number of proofs one challenge verifies, and the nonce
// input's script run.

// maxPaymentHeaderBytes caps the X402-Proof and X-Bsv-Payment values the gate
// decodes: 256 KiB (262,144 bytes). BRC-118 measured BEEF payments in a
// production x402 wallet (7,416 transactions): 4.9 KB on average and 155.7 KB
// for a 300-link unconfirmed chain, which is about 208 KB as base64 in a
// BRC-105 JSON header, under the cap. The same document puts proxy and CDN
// header limits at 8 to 16 KB and Cloudflare Workers at about 128 KB in total,
// so a larger header rarely arrives through a proxy. Anvil's own payments are
// far smaller: sdk/ts has no x402 client, and the proofs in payment_test.go are
// under 1 KB. An X402-Proof is base64 inside base64url JSON, so the cap still
// carries a raw transaction of about 147 KB; BRC-118 gives 200 to 700 bytes for
// one payment transaction. Without the cap the HTTP server's own 1 MiB header
// limit applies (net/http DefaultMaxHeaderBytes; cmd/anvil/main.go sets no
// MaxHeaderBytes).
const maxPaymentHeaderBytes = 256 << 10

// maxProofAttempts is how many proofs one challenge verifies: the first try
// and two retries. A proof is counted when it reaches the transaction decode,
// so one that fails the request binding or arrives after expiry is refused
// without counting, and only a caller that holds the challenge and repeats the
// exact request can use up its attempts. The retries are for a failure an
// honest client cannot avoid, such as ARC being unreachable at step 9 (each
// attempt already tries the failover ARC, ARCClient.Submit). A failed decode,
// script or payee check fails the same way on every retry of the same proof.
// Three attempts bound one challenge to three transaction decodes and three
// nonce script runs.
const maxProofAttempts = 3

// maxNonceUnlockingScriptBytes is the size of the largest P2PKH unlocking
// script: a signature push of at most 73 bytes and a public key push of at
// most 65 bytes, each behind a push opcode of at most 5 bytes (OP_PUSHDATA4):
// 5 + 73 + 5 + 65 = 148 bytes.
const maxNonceUnlockingScriptBytes = 148

// maxP2PKHSignatureBytes is a 72-byte DER signature (two 33-byte integers and
// 6 bytes of DER framing) followed by its 1-byte sighash type: 73 bytes.
const maxP2PKHSignatureBytes = 73

// nonceScriptFlags are the flags spv.Verify (go-sdk v1.7.7, spv/verify.go)
// verifies an unmined transaction with, BlockValidationFlags for an unmined
// spend of an unmined output on mainnet, without its two Chronicle bits. They
// include VerifySigPushOnly, VerifyLowS, VerifyNullFail, VerifyDERSignatures
// and VerifyStrictEncoding. Without Chronicle and UTXOAfterChronicle the nonce
// input keeps the epoch it was verified under before (WithAfterGenesis: an
// output created after Genesis, spent under Genesis rules), and those rules
// hold for every transaction version: under Chronicle the interpreter waives
// them, VerifySigPushOnly included, for a transaction version above 1.
var nonceScriptFlags = scriptflag.MainNetActivationHeights.BlockValidationFlags(math.MaxUint32, math.MaxUint32) &^
	(scriptflag.Chronicle | scriptflag.UTXOAfterChronicle)

// nonceScriptTimeout stops the interpreter on the nonce input. A spend that
// passes checkNonceUnlockingScript runs four opcodes and checks one signature,
// measured at about 0.15 ms per verification over 2,000 runs. The 2 s deadline
// is more than 10,000 times that, so it never cuts off a valid spend; it backs
// the shape check and the flags up. Before these bounds a 4 KB unlocking script
// ran for 7 to 13 s. A variable so tests can shorten it.
var nonceScriptTimeout = 2 * time.Second

// errPaymentHeaderTooLarge marks a payment header refused by its size.
var errPaymentHeaderTooLarge = errors.New("payment header too large")

// errNonceUnlockingNotP2PKH marks a nonce input refused before the interpreter.
var errNonceUnlockingNotP2PKH = errors.New("nonce unlocking script is not a P2PKH spend")

// checkPaymentHeaderSize refuses a payment header value longer than
// maxPaymentHeaderBytes. It reads only the length, so it runs before any
// decode.
func checkPaymentHeaderSize(name, value string) error {
	if len(value) > maxPaymentHeaderBytes {
		return fmt.Errorf("%w: %s is %d bytes, the limit is %d", errPaymentHeaderTooLarge, name, len(value), maxPaymentHeaderBytes)
	}
	return nil
}

// paymentRejectionStatus is the HTTP status for a rejected payment: 431 for a
// header refused by its size, 402 for everything else.
func paymentRejectionStatus(err error) int {
	if errors.Is(err, errPaymentHeaderTooLarge) {
		return http.StatusRequestHeaderFieldsTooLarge
	}
	return http.StatusPaymentRequired
}

// reserveProofAttempt counts one proof against the challenge stored under
// hash. It fails when the challenge is no longer pending, or when
// maxProofAttempts proofs have already been counted against it.
func (pg *PaymentGate) reserveProofAttempt(hash string, pending *pendingChallenge) error {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	if pg.pendingChallenges[hash] != pending {
		return fmt.Errorf("unknown or expired challenge")
	}
	if pending.attempts >= maxProofAttempts {
		return fmt.Errorf("challenge spent: %d proofs already tried, request a new challenge", maxProofAttempts)
	}
	pending.attempts++
	return nil
}

// endProofAttempt removes the challenge after a proof that passed, since a
// challenge pays for one request, and after a failed proof that used its last
// attempt.
func (pg *PaymentGate) endProofAttempt(hash string, pending *pendingChallenge, passed bool) {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	if pg.pendingChallenges[hash] != pending {
		return
	}
	if passed || pending.attempts >= maxProofAttempts {
		delete(pg.pendingChallenges, hash)
	}
}

// checkNonceUnlockingScript refuses, without running the interpreter, a nonce
// input that cannot be a P2PKH spend. The node mints every nonce output as
// P2PKH (WalletNonceProvider, p2pkh.Lock), and the only unlocking script that
// satisfies P2PKH is a signature push followed by a public key push. The check
// does not depend on the transaction version, which can waive
// VerifySigPushOnly under Chronicle rules.
func checkNonceUnlockingScript(locking, unlocking *bsvscript.Script) error {
	if !locking.IsP2PKH() {
		return fmt.Errorf("%w: the nonce locking script is not P2PKH", errNonceUnlockingNotP2PKH)
	}
	if len(*unlocking) > maxNonceUnlockingScriptBytes {
		return fmt.Errorf("%w: %d bytes, the most a P2PKH spend needs is %d",
			errNonceUnlockingNotP2PKH, len(*unlocking), maxNonceUnlockingScriptBytes)
	}
	chunks, err := bsvscript.DecodeScript(*unlocking)
	if err != nil {
		return fmt.Errorf("%w: %v", errNonceUnlockingNotP2PKH, err)
	}
	if len(chunks) != 2 || !isDataPush(chunks[0]) || !isDataPush(chunks[1]) {
		return fmt.Errorf("%w: want a signature push and a public key push", errNonceUnlockingNotP2PKH)
	}
	if n := len(chunks[0].Data); n > maxP2PKHSignatureBytes {
		return fmt.Errorf("%w: %d-byte signature, the most is %d", errNonceUnlockingNotP2PKH, n, maxP2PKHSignatureBytes)
	}
	if n := len(chunks[1].Data); n != 33 && n != 65 {
		return fmt.Errorf("%w: %d-byte public key, want 33 or 65", errNonceUnlockingNotP2PKH, n)
	}
	return nil
}

// isDataPush reports whether chunk pushes data with a push opcode
// (OP_DATA_1 to OP_PUSHDATA4). OP_0 and the small-integer opcodes push no
// data a P2PKH spend can use.
func isDataPush(chunk *bsvscript.ScriptChunk) bool {
	return chunk.Op >= bsvscript.OpDATA1 && chunk.Op <= bsvscript.OpPUSHDATA4
}

// runNonceScripts runs the unlocking script of the input at inputIdx against
// nonceOutput under nonceScriptFlags, and stops once nonceScriptTimeout has
// passed.
func runNonceScripts(tx *transaction.Transaction, inputIdx int, nonceOutput *transaction.TransactionOutput) error {
	ctx, cancel := context.WithTimeout(context.Background(), nonceScriptTimeout)
	defer cancel()
	return interpreter.NewEngine().Execute(
		interpreter.WithTx(tx, inputIdx, nonceOutput),
		interpreter.WithFlags(nonceScriptFlags),
		interpreter.WithContext(ctx),
	)
}
