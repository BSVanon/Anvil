package peerhygiene

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

const octetStream = "application/octet-stream"

var testQuestion = &lookup.LookupQuestion{Service: "ls_ship", Query: json.RawMessage(`{"topics":["tm_uhrp"]}`)}

// stubPeer is an overlay peer that answers every request with one canned reply
// and records the last request it received.
type stubPeer struct {
	url string

	mu                                     sync.Mutex
	method, path, contentType, aggregation string
	reqBody                                []byte
}

// newStubPeer serves body with status and contentType. When chunked is set the
// reply is streamed with no Content-Length.
func newStubPeer(t *testing.T, status int, contentType string, body []byte, chunked bool) *stubPeer {
	t.Helper()
	p := &stubPeer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.method, p.path, p.reqBody = r.Method, r.URL.Path, reqBody
		p.contentType, p.aggregation = r.Header.Get("Content-Type"), r.Header.Get("X-Aggregation")
		p.mu.Unlock()
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		if !chunked {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(status)
		if chunked {
			w.(http.Flusher).Flush() // headers go out before the length is known
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

// lookupVia runs f.Lookup against url and fails the test on a panic, which in
// production would kill the node: go-sdk's LookupResolver calls the
// facilitator in a goroutine with no recover.
func lookupVia(t *testing.T, f lookup.Facilitator, url string) (answer *lookup.LookupAnswer, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Lookup panicked instead of returning an error: %v", r)
		}
	}()
	return f.Lookup(context.Background(), url, testQuestion)
}

// expectLookupError serves an octet-stream body and requires an error
// containing want.
func expectLookupError(t *testing.T, body []byte, want string) {
	t.Helper()
	p := newStubPeer(t, http.StatusOK, octetStream, body, false)
	answer, err := lookupVia(t, &BoundedFacilitator{}, p.url)
	if err == nil {
		t.Fatalf("expected an error containing %q, got answer %+v", want, answer)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected an error containing %q, got: %v", want, err)
	}
}

// chainTxs returns n transactions above overlaytest's mined funding tx, each
// spending output 0 of the one before.
func chainTxs(t *testing.T, n int) []*transaction.Transaction {
	t.Helper()
	lock := script.Script{script.OpTRUE}
	txs := []*transaction.Transaction{overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1000})}
	for len(txs) < n {
		tx := transaction.NewTransaction()
		tx.AddInputFromTx(txs[len(txs)-1], 0, nil)
		tx.Inputs[0].UnlockingScript = &script.Script{}
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
		txs = append(txs, tx)
	}
	return txs
}

// sharedBEEF serializes tip and its whole ancestry as one BEEF.
func sharedBEEF(t *testing.T, tip *transaction.Transaction) []byte {
	t.Helper()
	beef, err := transaction.NewBeefFromTransaction(tip)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	b, err := beef.Bytes()
	if err != nil {
		t.Fatalf("Beef.Bytes: %v", err)
	}
	return b
}

type binaryEntry struct {
	tx      *transaction.Transaction
	index   uint32
	context []byte
}

// encodeBinaryAnswer writes the aggregated binary answer format: outpoints
// (display-order txid bytes, output index, context), then the shared BEEF.
func encodeBinaryAnswer(t *testing.T, beef []byte, entries ...binaryEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(util.VarInt(len(entries)).Bytes())
	for _, e := range entries {
		txid, err := hex.DecodeString(e.tx.TxID().String())
		if err != nil {
			t.Fatalf("txid hex: %v", err)
		}
		buf.Write(txid)
		buf.Write(util.VarInt(e.index).Bytes())
		buf.Write(util.VarInt(len(e.context)).Bytes())
		buf.Write(e.context)
	}
	buf.Write(beef)
	return buf.Bytes()
}

// assertParity requires the bounded and the upstream facilitator to decode
// the same reply into the same answer, and checks the request on the wire.
func assertParity(t *testing.T, contentType string, body []byte) *lookup.LookupAnswer {
	t.Helper()
	p := newStubPeer(t, http.StatusOK, contentType, body, false)
	got, err := lookupVia(t, &BoundedFacilitator{Client: http.DefaultClient}, p.url)
	if err != nil {
		t.Fatalf("bounded facilitator: %v", err)
	}
	want, err := (&lookup.HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}).Lookup(context.Background(), p.url, testQuestion)
	if err != nil {
		t.Fatalf("upstream facilitator: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("answers differ:\n bounded  %+v\n upstream %+v", got, want)
	}
	question, _ := json.Marshal(testQuestion)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.method != http.MethodPost || p.path != "/lookup" || p.contentType != "application/json" ||
		p.aggregation != "yes" || !bytes.Equal(p.reqBody, question) {
		t.Fatalf("request differs from upstream's: %s %s Content-Type=%q X-Aggregation=%q body=%s",
			p.method, p.path, p.contentType, p.aggregation, p.reqBody)
	}
	return got
}

// TestBoundedFacilitator_MatchesUpstreamOnValidBinaryAnswer: an honest
// aggregated answer, with a context and a repeated outpoint, decodes exactly
// as go-sdk v1.7.7's facilitator decodes it.
func TestBoundedFacilitator_MatchesUpstreamOnValidBinaryAnswer(t *testing.T) {
	txs := chainTxs(t, 2)
	body := encodeBinaryAnswer(t, sharedBEEF(t, txs[1]),
		binaryEntry{tx: txs[0]}, binaryEntry{tx: txs[1], context: []byte("ctx")}, binaryEntry{tx: txs[0]})
	got := assertParity(t, octetStream, body)
	if got.Type != lookup.AnswerTypeOutputList || len(got.Outputs) != 3 {
		t.Fatalf("expected a 3-output list, got %+v", got)
	}
}

// TestBoundedFacilitator_MatchesUpstreamOnJSONAnswers: output-list and
// freeform JSON answers decode exactly as upstream decodes them.
func TestBoundedFacilitator_MatchesUpstreamOnJSONAnswers(t *testing.T) {
	txBeef, err := chainTxs(t, 1)[0].BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}
	list, _ := json.Marshal(&lookup.LookupAnswer{
		Type:    lookup.AnswerTypeOutputList,
		Outputs: []*lookup.OutputListItem{{Beef: txBeef, OutputIndex: 0}},
	})
	if got := assertParity(t, "application/json", list); len(got.Outputs) != 1 {
		t.Fatalf("expected one output, got %+v", got)
	}
	assertParity(t, "application/json", []byte(`{"type":"freeform","result":{"hosts":["a"]}}`))
}

// TestBoundedFacilitator_Non200IsHTTPError: a failing peer gives the same
// *util.HTTPError as upstream, which the hygiene wrapper counts as a failure.
func TestBoundedFacilitator_Non200IsHTTPError(t *testing.T) {
	p := newStubPeer(t, http.StatusServiceUnavailable, "", nil, false)
	_, err := lookupVia(t, &BoundedFacilitator{}, p.url)
	var httpErr *util.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected a 503 *util.HTTPError, got: %v", err)
	}
}

// TestBoundedFacilitator_HugeOutpointCountRejected: a 9-byte reply declaring
// 2^32 outpoints. Upstream sizes its outpoint slice from that count (about
// 192 GiB), a fatal out-of-memory error that no recover can catch.
func TestBoundedFacilitator_HugeOutpointCountRejected(t *testing.T) {
	expectLookupError(t, []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
		"binary lookup: outpoint count 4294967296 exceeds capacity of 0 remaining bytes")
}

// TestBoundedFacilitator_FiveBytePanicBodyRejected: zero outpoints, then a
// 4-byte BEEF that is only the Atomic BEEF prefix. go-sdk v1.2.23 sliced past
// the end of it and panicked inside the resolver's goroutine. v1.7.7 checks
// the length, so this pins the upgraded parser behind the facilitator.
func TestBoundedFacilitator_FiveBytePanicBodyRejected(t *testing.T) {
	expectLookupError(t, []byte{0x00, 0x01, 0x01, 0x01, 0x01},
		"binary lookup: parsing BEEF: provided atomic BEEF length (4) is too short")
}

// TestBoundedFacilitator_HugeContextLenRejected: one outpoint whose context
// length is MaxInt64. Upstream's reader adds it to its position, the sum
// wraps negative past both of its checks, and the slice panics inside the
// resolver's goroutine.
func TestBoundedFacilitator_HugeContextLenRejected(t *testing.T) {
	expectLookupError(t, hugeContextLenBody(),
		"binary lookup: context[0] length 9223372036854775807 exceeds capacity of 0 remaining bytes")
}

// hugeContextLenBody is a binary answer with one outpoint whose context
// length is MaxInt64.
func hugeContextLenBody() []byte {
	body := append([]byte{0x01}, make([]byte, 32)...)                         // one outpoint, txid
	body = append(body, 0x00)                                                 // outputIndex 0
	return append(body, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F) // contextLen MaxInt64
}

// freeformOfSize returns a valid JSON freeform answer exactly n bytes long, so
// that only the size cap can reject it.
func freeformOfSize(n int) []byte {
	const head, tail = `{"type":"freeform","result":"`, `"}`
	return []byte(head + strings.Repeat("a", n-len(head)-len(tail)) + tail)
}

// TestBoundedFacilitator_OverCapBodyRejected: a reply one byte over MaxBytes
// is refused whether the peer declares its length or streams it, and a reply
// exactly at the cap is still accepted.
func TestBoundedFacilitator_OverCapBodyRejected(t *testing.T) {
	const capBytes = 128
	for _, tc := range []struct {
		name    string
		chunked bool
		want    string
	}{
		{"declared Content-Length", false, "Content-Length 129 is over 128 bytes"},
		{"streamed without a length", true, "body is over 128 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newStubPeer(t, http.StatusOK, "application/json", freeformOfSize(capBytes+1), tc.chunked)
			_, err := lookupVia(t, &BoundedFacilitator{MaxBytes: capBytes}, p.url)
			if !errors.Is(err, ErrLookupResponseTooLarge) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected ErrLookupResponseTooLarge with %q, got: %v", tc.want, err)
			}
		})
	}
	p := newStubPeer(t, http.StatusOK, "application/json", freeformOfSize(capBytes), true)
	if _, err := lookupVia(t, &BoundedFacilitator{MaxBytes: capBytes}, p.url); err != nil {
		t.Fatalf("a reply at the cap must be accepted, got: %v", err)
	}
}

// TestBoundedFacilitator_DefaultCapIsMaxLookupResponseBytes: the zero-value
// facilitator, as resolver.go builds it, caps replies at
// MaxLookupResponseBytes.
func TestBoundedFacilitator_DefaultCapIsMaxLookupResponseBytes(t *testing.T) {
	p := newStubPeer(t, http.StatusOK, "application/json", freeformOfSize(int(MaxLookupResponseBytes)+1), true)
	_, err := lookupVia(t, &BoundedFacilitator{}, p.url)
	if !errors.Is(err, ErrLookupResponseTooLarge) || !strings.Contains(err.Error(), "body is over 2097152 bytes") {
		t.Fatalf("expected the 2 MiB default cap, got: %v", err)
	}
}

// TestBoundedFacilitator_NullJSONOutputRejected: go-sdk's LookupResolver
// dereferences every output of an answer, so a null output would panic it.
func TestBoundedFacilitator_NullJSONOutputRejected(t *testing.T) {
	p := newStubPeer(t, http.StatusOK, "application/json", []byte(`{"type":"output-list","outputs":[null]}`), false)
	_, err := lookupVia(t, &BoundedFacilitator{}, p.url)
	if err == nil || !strings.Contains(err.Error(), "lookup: output 0 of the answer is null") {
		t.Fatalf("expected a null-output error, got: %v", err)
	}
}

// TestBoundedFacilitator_ExpansionBudgetBoundsReserialization: outpoints
// naming every transaction of a 30-transaction chain, each with an 8 KiB
// output, make each output carry the chain up to it: about 15 times the
// reply's 248 KiB in total, past MaxAnswerBEEFBytes. Naming only the first 20
// stays within it.
func TestBoundedFacilitator_ExpansionBudgetBoundsReserialization(t *testing.T) {
	txs := dataChainTxs(t, 30, 8<<10)
	entries := make([]binaryEntry, len(txs))
	for i, tx := range txs {
		entries[i] = binaryEntry{tx: tx}
	}
	shared := sharedBEEF(t, txs[len(txs)-1])
	if answer, err := parseBinaryLookupAnswer(encodeBinaryAnswer(t, shared, entries[:20]...)); err != nil || len(answer.Outputs) != 20 {
		t.Fatalf("the first 20 outputs must fit the budget: %v", err)
	}

	body := encodeBinaryAnswer(t, shared, entries...)
	p := newStubPeer(t, http.StatusOK, octetStream, body, false)
	_, err := lookupVia(t, &BoundedFacilitator{}, p.url)
	want := "binary lookup: re-serialized BEEF exceeds capacity of " + strconv.FormatInt(MaxAnswerBEEFBytes, 10) + " bytes"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q, got: %v", want, err)
	}
}

// dataChainTxs is chainTxs with an extra OP_RETURN output of size bytes on
// every transaction.
func dataChainTxs(t *testing.T, n, size int) []*transaction.Transaction {
	t.Helper()
	data := &script.Script{}
	_ = data.AppendOpcodes(script.OpFALSE, script.OpRETURN)
	if err := data.AppendPushData(bytes.Repeat([]byte{0xCD}, size)); err != nil {
		t.Fatalf("AppendPushData: %v", err)
	}
	lock := script.Script{script.OpTRUE}
	txs := []*transaction.Transaction{overlaytest.SpendingTx(t,
		&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1000},
		&transaction.TransactionOutput{LockingScript: data})}
	for len(txs) < n {
		tx := transaction.NewTransaction()
		tx.AddInputFromTx(txs[len(txs)-1], 0, nil)
		tx.Inputs[0].UnlockingScript = &script.Script{}
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
		tx.AddOutput(&transaction.TransactionOutput{LockingScript: data})
		txs = append(txs, tx)
	}
	return txs
}

// TestBoundedFacilitator_DecodePanicBecomesError: if decoding ever panics,
// the facilitator must return an error rather than let the panic kill the
// resolver's goroutine and the node with it.
func TestBoundedFacilitator_DecodePanicBecomesError(t *testing.T) {
	orig := newBeefFromBytes
	newBeefFromBytes = func([]byte) (*transaction.Beef, error) { panic("decoder bug") }
	t.Cleanup(func() { newBeefFromBytes = orig })

	expectLookupError(t, []byte{0x00, 0x01, 0x00, 0xBE, 0xEF}, "lookup: decoding answer panicked: decoder bug")
}

// TestResolver_HostileAnswerIsAnErrorNotACrash: NewResolver sends per-host
// lookups through BoundedFacilitator, behind the backoff wrapper. A reply that
// makes go-sdk's own facilitator panic inside the resolver's goroutine, where
// nothing can recover it, must only fail that host's lookup.
func TestResolver_HostileAnswerIsAnErrorNotACrash(t *testing.T) {
	r := NewResolver(overlay.NetworkMainnet, nil)
	hygiene, ok := r.inner.Facilitator.(*Facilitator)
	if !ok {
		t.Fatalf("resolver must use the backoff wrapper, got %T", r.inner.Facilitator)
	}
	if _, ok := hygiene.inner.(*BoundedFacilitator); !ok {
		t.Fatalf("backoff wrapper must wrap BoundedFacilitator, got %T", hygiene.inner)
	}

	p := newStubPeer(t, http.StatusOK, octetStream, hugeContextLenBody(), false)
	r.SetSLAPTrackers([]string{p.url})
	_, err := r.Query(context.Background(), &lookup.LookupQuestion{Service: "ls_slap", Query: json.RawMessage(`{"service":"ls_ship"}`)})
	if err == nil || err.Error() != "no-successful-responses" {
		t.Fatalf("expected the hostile host's lookup to fail, got: %v", err)
	}
}
