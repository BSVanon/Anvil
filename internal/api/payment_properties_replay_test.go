package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/txrelay"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type paymentRoundTripFunc func(*http.Request) (*http.Response, error)

func (f paymentRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// usePaymentTransport replaces the transport used by a newly constructed ARC
// client. It keeps these tests in-process: no listener is needed.
func usePaymentTransport(t *testing.T, f paymentRoundTripFunc) *txrelay.ARCClient {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = old })
	return txrelay.NewARCClient("http://arc.invalid", "")
}

func arcJSONResponse(t *testing.T, r *http.Request, status string) *http.Response {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil {
		t.Fatalf("parse ARC submission: %v", err)
	}
	body, _ := json.Marshal(txrelay.ARCResponse{TxID: tx.TxID().String(), Status: status})
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}
}

func brc121PaymentParts(t *testing.T, f *brc121Fix, h map[string]string) (*brc121Payment, string, string) {
	t.Helper()
	headers := make(http.Header)
	for k, v := range h {
		headers.Set(k, v)
	}
	p, beef, err := readBRC121Headers(headers, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.readBRC121BEEF(beef, 100); err != nil {
		t.Fatal(err)
	}
	ef, err := p.tx.EFHex()
	if err != nil {
		t.Fatal(err)
	}
	return p, hex.EncodeToString(*p.tx.Outputs[p.vout].LockingScript), ef
}

func useAsProof(t *testing.T, pg *PaymentGate, tx *transaction.Transaction, payee string) error {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Host = "localhost"
	ch := &X402Challenge{V: 1, Scheme: "bsv-tx-v1", Domain: req.Host, Method: req.Method,
		Path: req.URL.Path, ReqHeadersSHA256: canonicalHeaderHash(req), ReqBodySHA256: sha256Hex(nil),
		AmountSats: 100, PayeeLockingScriptHex: payee, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	b, _ := json.Marshal(ch)
	hash := sha256Hex(b)
	pg.mu.Lock()
	pg.pendingChallenges[hash] = &pendingChallenge{challenge: ch, payees: []Payee{{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100}}}
	pg.mu.Unlock()
	req.Header.Set(HeaderX402Proof, proofCarrying(t, ch, tx.Bytes()))
	_, err := pg.verifyProof(httptest.NewRecorder(), req, req.Header.Get(HeaderX402Proof))
	return err
}

// BRC-120 requires nonce replay protection and settlement-gated execution
// (0120.md:40-47). BRC-121 independently refuses a wallet merge
// (0121.md:85-101). The same txid is claimed by all three paths here.
func TestPaymentPropertyOneTransactionUnlocksOneRequest(t *testing.T) {
	usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
		return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
	})
	for _, first := range []string{"proof", "direct", "brc121"} {
		t.Run(first, func(t *testing.T) {
			f := newBRC121Fix(t, 100)
			h := f.payment(t, 100, brc121Pay{})
			p, payee, ef := brc121PaymentParts(t, f, h)
			payees := []Payee{{Role: "infrastructure", LockingScriptHex: payee, AmountSats: 100}}
			uses := map[string]func() bool{
				"proof": func() bool { return useAsProof(t, f.pg, p.tx, payee) == nil },
				"direct": func() bool {
					_, err := f.pg.verifyDirectPayment(context.Background(), ef, payees)
					return err == nil
				},
				"brc121": func() bool { return f.serve(brc121Path, "192.0.2.1:1", h).Code == http.StatusOK },
			}
			order := []string{first}
			for _, path := range []string{"proof", "direct", "brc121"} {
				if path != first {
					order = append(order, path)
				}
			}
			succeeded := 0
			for _, path := range order {
				if uses[path]() {
					succeeded++
				}
			}
			if succeeded != 1 {
				t.Fatalf("transaction served %d requests in order %v, want one", succeeded, order)
			}
		})
	}

	t.Run("record survives restart", func(t *testing.T) {
		f := newBRC121Fix(t, 100)
		h := f.payment(t, 100, brc121Pay{})
		if w := f.serve(brc121Path, "192.0.2.1:1", h); w.Code != http.StatusOK {
			t.Fatalf("first use: %d %s", w.Code, w.Body.String())
		}
		f.pg.replays = newPaymentReplaySet(time.Hour, 16, time.Now)
		w := f.serve(brc121Path, "192.0.2.1:1", h)
		if w.Code != http.StatusPaymentRequired || codeOf(t, w) != codeBRC121Replayed {
			t.Fatalf("after restart: got %d %s", w.Code, w.Body.String())
		}
	})
}

func noPaymentOffer(w *httptest.ResponseRecorder) bool {
	return w.Header().Get(HeaderX402Challenge) == "" && w.Header().Get(headerBRC121Sats) == ""
}

// Once submission has begun, a transitional or lost ARC answer is ambiguous. Every path must
// answer 503 without selling a second transaction, then let the same tx retry
// once. The reference BRC-121 middleware applies this rule at server.ts:437-446.
func TestPaymentPropertyAmbiguousOutcomeRetriesSameTransactionOnce(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		var calls atomic.Int32
		arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return arcJSONResponse(t, r, "QUEUED"), nil
			}
			return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
		})
		srv := testServerWithPaymentGate(t, 100)
		srv.paymentGate.arcClient = arc
		ef := signedEFPaying(t, paidOut{testPayeeScript(t), 100})
		first := serveDirectPayment(srv, "/stats", ef)
		second := serveDirectPayment(srv, "/stats", ef)
		third := serveDirectPayment(srv, "/stats", ef)
		if first.Code != http.StatusServiceUnavailable || !noPaymentOffer(first) || second.Code != http.StatusOK || third.Code != http.StatusPaymentRequired || calls.Load() != 2 {
			t.Fatalf("codes %d, %d, %d; ARC calls %d", first.Code, second.Code, third.Code, calls.Load())
		}
	})

	t.Run("proof", func(t *testing.T) {
		var calls atomic.Int32
		arc := usePaymentTransport(t, func(r *http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return arcJSONResponse(t, r, "QUEUED"), nil
			}
			return arcJSONResponse(t, r, "SEEN_ON_NETWORK"), nil
		})
		srv := testServerWithPaymentGate(t, 100)
		srv.paymentGate.arcClient, srv.paymentGate.requireMempool = arc, true
		ch := getChallenge(t, srv, http.MethodGet, "/stats")
		proof := buildProof(t, ch, 100, testPayeeScript(t))
		pay := func() *httptest.ResponseRecorder {
			return getWithHeaders(srv, "/stats", map[string]string{HeaderX402Proof: proof})
		}
		first, second, third := pay(), pay(), pay()
		if first.Code != http.StatusServiceUnavailable || !noPaymentOffer(first) || second.Code != http.StatusOK || third.Code != http.StatusPaymentRequired || calls.Load() != 2 {
			t.Fatalf("codes %d, %d, %d; ARC calls %d", first.Code, second.Code, third.Code, calls.Load())
		}
	})

	t.Run("brc121", func(t *testing.T) {
		f := newBRC121Fix(t, 100)
		var calls atomic.Int32
		f.pg.brc121.submit = func(_ context.Context, p *brc121Payment, _ bool) (*txrelay.ARCResponse, error) {
			if calls.Add(1) == 1 {
				return nil, errors.New("ARC reply lost")
			}
			return &txrelay.ARCResponse{TxID: p.txid.String(), Status: "SEEN_ON_NETWORK"}, nil
		}
		h := f.payment(t, 100, brc121Pay{})
		pay := func() *httptest.ResponseRecorder { return f.serve(brc121Path, "192.0.2.1:1", h) }
		first, second, third := pay(), pay(), pay()
		if first.Code != http.StatusServiceUnavailable || !noPaymentOffer(first) || second.Code != http.StatusOK || third.Code != http.StatusPaymentRequired || calls.Load() != 2 {
			t.Fatalf("codes %d, %d, %d; ARC calls %d", first.Code, second.Code, third.Code, calls.Load())
		}
	})
}
