package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/BSVanon/Anvil/internal/beefscan"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	bsvscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

// brc121Window is how far x-bsv-time may be from the node's clock (BRC-121
// section 5, step 2; 402-pay constants.ts:28). Exactly 30 seconds passes, as
// in the reference middleware (server.ts:127).
const brc121Window = 30 * time.Second

// brc121Protocol is BRC-29's key-derivation protocol (402-pay constants.ts:4;
// the toolbox's brc29.Protocol), under which a payment's key is derived.
var brc121Protocol = sdk.Protocol{SecurityLevel: sdk.SecurityLevelEveryAppAndCounterparty, Protocol: "3241645161d8"}

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER, the bound of the
// reference middleware's parseUnsignedInteger (server.ts:44-48).
const maxSafeInteger = 1<<53 - 1

var (
	brc121UnsignedRe   = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	brc121CompressedRe = regexp.MustCompile(`^(02|03)[0-9a-fA-F]{64}$`)
	brc121Base64Re     = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
)

// brc121Payment is a BRC-121 payment once its headers and BEEF are read.
type brc121Payment struct {
	sender *ec.PublicKey
	nonce  string // the derivation prefix, canonical base64
	time   string // the millisecond timestamp, as sent; its base64 is the suffix
	vout   uint32
	tx     *transaction.Transaction // the subject, its inputs linked to the BEEF's
	txid   chainhash.Hash
	atomic []byte // the subject and its kept ancestry, as an Atomic BEEF
	sats   uint64 // what output vout pays
	client [32]byte
}

func refuseMalformed(format string, a ...interface{}) error {
	return brc121Refuse(codeBRC121Malformed, fmt.Sprintf(format, a...))
}

// readBRC121Headers checks the five payment headers as the reference
// middleware does (server.ts:107-127, 150-151): all present, within its
// length limits, the sender a compressed public key, the nonce canonical
// base64, time and vout unsigned safe integers, and time within brc121Window
// of now. x-bsv-beef is held to the X-Bsv-Payment header cap.
func readBRC121Headers(h http.Header, now time.Time) (*brc121Payment, string, error) {
	beef, sender := h.Get(headerBRC121Beef), h.Get(headerBRC121Sender)
	nonce, ts, vout := h.Get(headerBRC121Nonce), h.Get(headerBRC121Time), h.Get(headerBRC121Vout)
	if beef == "" || sender == "" || nonce == "" || ts == "" || vout == "" {
		return nil, "", refuseMalformed("a BRC-121 payment needs all five headers: %s, %s, %s, %s and %s",
			headerBRC121Beef, headerBRC121Sender, headerBRC121Nonce, headerBRC121Time, headerBRC121Vout)
	}
	if len(sender) > 130 || len(nonce) > 512 || len(ts) > 16 || len(vout) > 10 {
		return nil, "", refuseMalformed("a payment header is longer than BRC-121 allows")
	}
	if err := checkPaymentHeaderSize(headerBRC121Beef, beef); err != nil {
		return nil, "", refuseMalformed("%v", err)
	}
	if !canonicalBase64(beef) {
		return nil, "", refuseMalformed("%s is not canonical base64", headerBRC121Beef)
	}
	key, err := compressedKey(sender)
	if !brc121CompressedRe.MatchString(sender) || err != nil || key.ToDERHex() != strings.ToLower(sender) {
		return nil, "", refuseMalformed("%s is not a compressed public key", headerBRC121Sender)
	}
	if !canonicalBase64(nonce) {
		return nil, "", refuseMalformed("%s is not canonical base64", headerBRC121Nonce)
	}
	if err := checkBRC121Time(ts, now); err != nil {
		return nil, "", err
	}
	index, ok := unsignedSafe(vout)
	if !ok || index > 1<<32-1 {
		return nil, "", refuseMalformed("%s is not an output index", headerBRC121Vout)
	}
	return &brc121Payment{sender: key, nonce: nonce, time: ts, vout: uint32(index)}, beef, nil
}

func checkBRC121Time(ts string, now time.Time) error {
	millis, ok := unsignedSafe(ts)
	if !ok {
		return refuseMalformed("%s is not a millisecond timestamp", headerBRC121Time)
	}
	// In whole milliseconds, as the reference middleware compares them.
	if d := time.Duration(now.UnixMilli()-int64(millis)) * time.Millisecond; d > brc121Window || d < -brc121Window {
		return brc121Refuse(codeBRC121Stale, fmt.Sprintf("%s is %s from this node's clock; the most BRC-121 allows is %s",
			headerBRC121Time, d, brc121Window))
	}
	return nil
}

// canonicalBase64 is the reference middleware's isCanonicalBase64
// (server.ts:59-64): padded standard base64 that encodes back to itself.
func canonicalBase64(s string) bool {
	if !brc121Base64Re.MatchString(s) {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && base64.StdEncoding.EncodeToString(b) == s
}

func unsignedSafe(s string) (uint64, bool) {
	if !brc121UnsignedRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && n <= maxSafeInteger
}

// readBRC121BEEF reads x-bsv-beef into p: an Atomic BEEF (BRC-95) whose
// subject is held as a transaction, read through beefnorm.Parse, which
// prices it first, parses it in one pass and keeps only the subject and the
// ancestry verifying it reads. So pricing and recording see only the
// subject's dependency closure, as the reference middleware's toBinaryAtomic
// restricts them (server.ts:136-140), and unrelated entries are dropped. The
// subject may have at most maxDirectPaymentInputs inputs, each backed by its
// source transaction, and output vout must pay at least price.
func (p *brc121Payment) readBRC121BEEF(beef string, price int) error {
	raw, err := base64.StdEncoding.DecodeString(beef)
	if err != nil {
		return refuseMalformed("%s is not base64", headerBRC121Beef)
	}
	n, err := parseBRC121BEEF(raw)
	if err != nil {
		return brc121Refuse(codeBRC121BadBEEF, fmt.Sprintf("%s is not a BEEF this node reads: %v", headerBRC121Beef, err))
	}
	if used := beefscan.Consumed(raw); used != len(raw) {
		return brc121Refuse(codeBRC121BadBEEF, fmt.Sprintf("%s has %d trailing bytes", headerBRC121Beef, len(raw)-used))
	}
	if n.Format != transaction.ATOMIC_BEEF {
		return brc121Refuse(codeBRC121BadBEEF, headerBRC121Beef+" must be an Atomic BEEF (BRC-95)")
	}
	if err := n.Unbacked(); err != nil {
		return brc121Refuse(codeBRC121BadBEEF, err.Error())
	}
	if len(n.Tx.Inputs) == 0 || len(n.Tx.Inputs) > maxDirectPaymentInputs {
		return brc121Refuse(codeBRC121BadBEEF, fmt.Sprintf("the payment has %d inputs; a payment needs 1 to %d",
			len(n.Tx.Inputs), maxDirectPaymentInputs))
	}
	if int64(p.vout) >= int64(len(n.Tx.Outputs)) {
		return brc121Refuse(codeBRC121Underpaid, fmt.Sprintf("the payment has no output %d", p.vout))
	}
	if out := n.Tx.Outputs[p.vout]; out.Satoshis < uint64(price) {
		return brc121Refuse(codeBRC121Underpaid, fmt.Sprintf("output %d pays %d sats; the price is %d", p.vout, out.Satoshis, price))
	}
	atomic, err := n.Atomic()
	if err != nil {
		return brc121Refuse(codeBRC121BadBEEF, fmt.Sprintf("serialize the payment's BEEF: %v", err))
	}
	p.tx, p.txid, p.atomic, p.sats = n.Tx, *n.Subject, atomic, n.Tx.Outputs[p.vout].Satoshis
	return nil
}

// parseBRC121BEEF is beefnorm.Parse, with a panic in it refused.
func parseBRC121BEEF(raw []byte) (n *beefnorm.BEEF, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = nil, fmt.Errorf("BEEF parse panicked: %v", r)
		}
	}()
	return beefnorm.Parse(raw)
}

// brc121KeyID is the BRC-29 key ID a payment is derived under: the nonce, a
// space, and base64 of the time's UTF-8 bytes (BRC-121 section 3, step 5;
// 402-pay client.ts:51-60). Under brc121Protocol it makes the BRC-42 invoice
// number 2-3241645161d8-<nonce> <base64(time)>.
func brc121KeyID(nonce, ts string) string {
	return nonce + " " + base64.StdEncoding.EncodeToString([]byte(ts))
}

// checkDerivation refuses p unless output vout is P2PKH to the key the node
// wallet derives for itself from p's sender, nonce and time: the check the
// toolbox makes when it records the payment (brc29.LockForSelf,
// validate_internalize_action_args.go:77-95), made before anything is sent
// to ARC, so the node never relays a transaction that does not pay it.
func (b *brc121Gate) checkDerivation(ctx context.Context, p *brc121Payment) error {
	forSelf := true
	res, err := b.wallet.GetPublicKey(ctx, sdk.GetPublicKeyArgs{
		EncryptionArgs: sdk.EncryptionArgs{
			ProtocolID:   brc121Protocol,
			KeyID:        brc121KeyID(p.nonce, p.time),
			Counterparty: sdk.Counterparty{Type: sdk.CounterpartyTypeOther, Counterparty: p.sender},
		},
		ForSelf: &forSelf,
	}, brc121Originator)
	if err != nil || res == nil || res.PublicKey == nil {
		return errBRC121Wallet(fmt.Sprintf("the node wallet could not derive the payment key: %v", err))
	}
	addr, err := bsvscript.NewAddressFromPublicKey(res.PublicKey, true)
	if err != nil {
		return errBRC121Wallet(fmt.Sprintf("the node wallet derived a key it cannot pay to: %v", err))
	}
	want, err := p2pkh.Lock(addr)
	if err != nil {
		return errBRC121Wallet(fmt.Sprintf("build the payment's locking script: %v", err))
	}
	got := p.tx.Outputs[p.vout].LockingScript
	if got == nil || !bytes.Equal(*got, *want) {
		return brc121Refuse(codeBRC121WrongKey, fmt.Sprintf("output %d does not pay the key this node derives for %s, %s and %s",
			p.vout, headerBRC121Sender, headerBRC121Nonce, headerBRC121Time))
	}
	return nil
}
