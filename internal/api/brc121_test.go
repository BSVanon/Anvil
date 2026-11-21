package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdk "github.com/bsv-blockchain/go-sdk/wallet"
)

const brc121Path = "/data?topic=brc121"

// TestBRC121ReferenceClientPaymentAccepted: a payment built as the reference
// client builds it is checked, sent to ARC once, recorded in the node wallet
// and served with node coverage of what it paid.
func TestBRC121ReferenceClientPaymentAccepted(t *testing.T) {
	f := newBRC121Fix(t, 100)
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusOK || w.Body.String() != "node-coverage=100" {
		t.Fatalf("want 200 with node coverage 100, got %d %s", w.Code, w.Body.String())
	}
	if n := f.arc.calls.Load(); n != 1 {
		t.Fatalf("want one ARC submit, got %d", n)
	}
	if internalizes, held := f.wallet.recorded(); internalizes != 1 || held != 1 {
		t.Fatalf("want the payment recorded once, got %d internalizes, %d held", internalizes, held)
	}
	if w.Header().Get(HeaderX402Receipt) == "" {
		t.Fatal("an accepted payment carries a receipt header")
	}
}

// TestBRC121InvoiceNumberPinned pins the BRC-42 invoice number BRC-121
// derives under (section 3, step 5): 2-3241645161d8-<nonce> <base64(time)>.
// The node wallet's derivation for itself and a key derived from that literal
// string are the same key.
func TestBRC121InvoiceNumberPinned(t *testing.T) {
	node, _ := ec.NewPrivateKey()
	sender, _ := ec.NewPrivateKey()
	nonce, ts := "AAECAwQFBgc=", "1719500000000"
	if got, want := brc121KeyID(nonce, ts), "AAECAwQFBgc= MTcxOTUwMDAwMDAwMA=="; got != want {
		t.Fatalf("key ID %q, want %q", got, want)
	}
	viaWallet, err := sdk.NewKeyDeriver(node).DerivePublicKey(brc121Protocol, brc121KeyID(nonce, ts),
		sdk.Counterparty{Type: sdk.CounterpartyTypeOther, Counterparty: sender.PubKey()}, true)
	if err != nil {
		t.Fatal(err)
	}
	literal, err := node.DeriveChild(sender.PubKey(), "2-3241645161d8-AAECAwQFBgc= MTcxOTUwMDAwMDAwMA==")
	if err != nil {
		t.Fatal(err)
	}
	if !viaWallet.IsEqual(literal.PubKey()) {
		t.Fatal("the node's derivation is not the one the literal BRC-121 invoice number gives")
	}
	if base64.StdEncoding.EncodeToString([]byte(ts)) != "MTcxOTUwMDAwMDAwMA==" {
		t.Fatal("the suffix is base64 of the time's UTF-8 bytes")
	}
}

// TestBRC121RefusalsBeforeARC: each payment that fails a check before ARC is
// refused 402 with its code and the offer repeated, and never reaches ARC or
// the wallet's record.
func TestBRC121RefusalsBeforeARC(t *testing.T) {
	other, _ := ec.NewPrivateKey()
	cases := []struct {
		name string
		code string
		req  func(f *brc121Fix) map[string]string
	}{
		{"a header missing", codeBRC121Malformed, func(f *brc121Fix) map[string]string {
			return withHeader(f.payment(t, 100, brc121Pay{}), headerBRC121Nonce, "")
		}},
		{"31 s stale", codeBRC121Stale, func(f *brc121Fix) map[string]string {
			return f.payer.pay(t, f.server(), 100, f.now.Add(-31*time.Second), brc121Pay{})
		}},
		{"31 s in the future", codeBRC121Stale, func(f *brc121Fix) map[string]string {
			return f.payer.pay(t, f.server(), 100, f.now.Add(31*time.Second), brc121Pay{})
		}},
		{"a nonce that is not canonical base64", codeBRC121Malformed, func(f *brc121Fix) map[string]string {
			return withHeader(f.payment(t, 100, brc121Pay{}), headerBRC121Nonce, "AAECAwQFBgc")
		}},
		{"a BEEF that is not base64", codeBRC121Malformed, func(f *brc121Fix) map[string]string {
			return withHeader(f.payment(t, 100, brc121Pay{}), headerBRC121Beef, "not base64!")
		}},
		{"a BEEF that is not canonical base64", codeBRC121Malformed, func(f *brc121Fix) map[string]string {
			h := f.payment(t, 100, brc121Pay{})
			return withHeader(h, headerBRC121Beef, h[headerBRC121Beef][:4]+"\n"+h[headerBRC121Beef][4:])
		}},
		{"a sender key that is not canonical", codeBRC121Malformed, func(f *brc121Fix) map[string]string {
			h := f.payment(t, 100, brc121Pay{})
			return withHeader(h, headerBRC121Sender, "04"+h[headerBRC121Sender][2:])
		}},
		{"vout out of range", codeBRC121Underpaid, func(f *brc121Fix) map[string]string {
			return withHeader(f.payment(t, 100, brc121Pay{}), headerBRC121Vout, "1")
		}},
		{"an amount below the price", codeBRC121Underpaid, func(f *brc121Fix) map[string]string {
			return f.payment(t, 99, brc121Pay{})
		}},
		{"a payment to another key", codeBRC121WrongKey, func(f *brc121Fix) map[string]string {
			return f.payment(t, 100, brc121Pay{payTo: other.PubKey()})
		}},
		{"a BEEF that is not atomic", codeBRC121BadBEEF, func(f *brc121Fix) map[string]string {
			return f.payment(t, 100, brc121Pay{plain: true})
		}},
		{"more than 10 inputs", codeBRC121BadBEEF, func(f *brc121Fix) map[string]string {
			return f.payment(t, 100, brc121Pay{inputs: 11})
		}},
		{"a bad input script", codeBRC121Unverifiable, func(f *brc121Fix) map[string]string {
			return f.payment(t, 100, brc121Pay{wrongSig: true})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBRC121Fix(t, 100)
			w := f.serve(brc121Path, "10.0.0.1:1", tc.req(f))
			if w.Code != http.StatusPaymentRequired || codeOf(t, w) != tc.code {
				t.Fatalf("want 402 %s, got %d %s", tc.code, w.Code, w.Body.String())
			}
			if w.Header().Get(headerBRC121Sats) != "100" || w.Header().Get(headerBRC121Server) != f.server().ToDERHex() {
				t.Fatalf("a refusal repeats the offer, got %q %q", w.Header().Get(headerBRC121Sats), w.Header().Get(headerBRC121Server))
			}
			if n := f.arc.calls.Load(); n != 0 {
				t.Fatalf("a payment refused before ARC reached ARC %d times", n)
			}
			if internalizes, _ := f.wallet.recorded(); internalizes != 0 {
				t.Fatal("a refused payment reached the wallet's record")
			}
			if n, _ := f.pg.brc121.journal.stats(f.now); n != 0 {
				t.Fatal("a payment refused before ARC was journaled")
			}
		})
	}
}

// TestBRC121TimeWindowEdges: exactly 30 s either way passes, as the
// reference middleware's abs(now - time) > window refusal lets it
// (server.ts:127).
func TestBRC121TimeWindowEdges(t *testing.T) {
	for _, d := range []time.Duration{30 * time.Second, -30 * time.Second} {
		f := newBRC121Fix(t, 100)
		w := f.serve(brc121Path, "10.0.0.1:1", f.payer.pay(t, f.server(), 100, f.now.Add(d), brc121Pay{}))
		if w.Code != http.StatusOK {
			t.Fatalf("a payment %s from the clock: want 200, got %d %s", d, w.Code, w.Body.String())
		}
	}
}

// TestBRC121UnrelatedBEEFEntriesIgnored: an Atomic BEEF holding a
// transaction outside the payment's ancestry is accepted, and the wallet is
// given only the payment's closure: the fake wallet, like go-sdk's
// NewBeefFromAtomicBytes, refuses the whole BEEF.
func TestBRC121UnrelatedBEEFEntriesIgnored(t *testing.T) {
	f := newBRC121Fix(t, 100)
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{unrelated: true}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
}

// TestBRC121MixedMethodsRefused: x-bsv-beef with X-Bsv-Payment or X402-Proof
// is answered 400, before ARC.
func TestBRC121MixedMethodsRefused(t *testing.T) {
	for _, other := range []string{HeaderBSVPayment, HeaderX402Proof} {
		f := newBRC121Fix(t, 100)
		w := f.serve(brc121Path, "10.0.0.1:1", withHeader(f.payment(t, 100, brc121Pay{}), other, "x"))
		if w.Code != http.StatusBadRequest || codeOf(t, w) != codeBRC121MixedMethods || f.arc.calls.Load() != 0 {
			t.Fatalf("%s with x-bsv-beef: want 400 %s before ARC, got %d %s (%d ARC calls)",
				other, codeBRC121MixedMethods, w.Code, w.Body.String(), f.arc.calls.Load())
		}
	}
}

// TestBRC121FreeRouteIgnoresHeaders: on a route the node does not price, the
// BRC-121 headers are ignored: the request is served, nothing is sent to ARC
// and nothing is recorded.
func TestBRC121FreeRouteIgnoresHeaders(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.pg.endpointPrices = map[string]int{"/data": 0}
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusOK || w.Body.String() != "node-coverage=0" || f.arc.calls.Load() != 0 {
		t.Fatalf("want 200 with no coverage and no ARC call, got %d %s (%d ARC calls)", w.Code, w.Body.String(), f.arc.calls.Load())
	}
	if internalizes, _ := f.wallet.recorded(); internalizes != 0 {
		t.Fatal("a free route recorded a payment")
	}
}

// TestBRC121WalletDerivationFailureIs500: a node wallet that cannot derive
// the payment key answers 500 (BRC-121 section 7), before ARC.
func TestBRC121WalletDerivationFailureIs500(t *testing.T) {
	f := newBRC121Fix(t, 100)
	f.pg.brc121.wallet = brokenDeriveWallet{f.wallet}
	w := f.serve(brc121Path, "10.0.0.1:1", f.payment(t, 100, brc121Pay{}))
	if w.Code != http.StatusInternalServerError || codeOf(t, w) != codeBRC121WalletUnavailable || f.arc.calls.Load() != 0 {
		t.Fatalf("want 500 %s before ARC, got %d %s", codeBRC121WalletUnavailable, w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "derive") {
		t.Fatalf("the message names the derivation: %s", w.Body.String())
	}
}

type brokenDeriveWallet struct{ *fakeBRC121Wallet }

func (brokenDeriveWallet) GetPublicKey(context.Context, sdk.GetPublicKeyArgs, string) (*sdk.GetPublicKeyResult, error) {
	return nil, errors.New("the wallet is down")
}
