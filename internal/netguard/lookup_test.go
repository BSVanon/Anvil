package netguard

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

const octetStream = "application/octet-stream"

var (
	slapQuestion = &lookup.LookupQuestion{Service: "ls_slap", Query: json.RawMessage(`{"service":"ls_ship"}`)}
	shipQuestion = &lookup.LookupQuestion{Service: "ls_ship", Query: json.RawMessage(`{"topics":["tm_test"]}`)}

	// countBomb declares 2^32 outpoints in 9 bytes. go-sdk's facilitator
	// sizes a slice from the count: a fatal out-of-memory error.
	countBomb = []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
)

// hugeContextLenBody declares one outpoint whose context length is MaxInt64.
// go-sdk's reader adds it to its position, the sum wraps negative, and the
// slice panics in the resolver's goroutine.
func hugeContextLenBody() []byte {
	body := append([]byte{0x01}, make([]byte, 33)...) // one outpoint: txid, outputIndex 0
	return append(body, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F)
}

// binaryAnswer writes the aggregated binary answer format: one outpoint per
// (tx, index) pair, in display-order txid bytes with no context, then beef.
func binaryAnswer(t *testing.T, beef []byte, txs []*transaction.Transaction, index uint64) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(util.VarInt(len(txs)).Bytes())
	for _, tx := range txs {
		txid, err := hex.DecodeString(tx.TxID().String())
		if err != nil {
			t.Fatalf("txid hex: %v", err)
		}
		buf.Write(txid)
		buf.Write(util.VarInt(index).Bytes())
		buf.WriteByte(0x00)
	}
	buf.Write(beef)
	return buf.Bytes()
}

// spendingTx returns a transaction above overlaytest's mined funding tx with
// one output carrying data, and its V1 BEEF.
func spendingTx(t *testing.T, data []byte) (*transaction.Transaction, []byte) {
	t.Helper()
	s := &script.Script{}
	_ = s.AppendOpcodes(script.OpFALSE, script.OpRETURN)
	if err := s.AppendPushData(data); err != nil {
		t.Fatalf("AppendPushData: %v", err)
	}
	tx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: s, Satoshis: 0})
	beef, err := tx.BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}
	return tx, beef
}

func jsonOutputList(t *testing.T, beef []byte, index uint32) []byte {
	t.Helper()
	body, err := json.Marshal(&lookup.LookupAnswer{
		Type:    lookup.AnswerTypeOutputList,
		Outputs: []*lookup.OutputListItem{{Beef: beef, OutputIndex: index}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// freeformOfSize returns a valid freeform JSON answer exactly n bytes long.
func freeformOfSize(n int) []byte {
	const head, tail = `{"type":"freeform","result":"`, `"}`
	return []byte(head + strings.Repeat("a", n-len(head)-len(tail)) + tail)
}

// serveAnswer serves body with contentType to every request, streamed with no
// Content-Length when chunked is set, and counts the requests.
func serveAnswer(t *testing.T, contentType string, body []byte, chunked bool) (string, *atomic.Int64) {
	t.Helper()
	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", contentType)
		if !chunked {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(http.StatusOK)
		if chunked {
			w.(http.Flusher).Flush()
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// noPanic runs f and fails the test if it panics in this goroutine. A panic in
// one of the resolver's own goroutines cannot be caught and ends the test
// binary instead, which fails the run just the same.
func noPanic(t *testing.T, what string, f func() error) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	return f()
}

// TestGuard_StockLookupStackSurvivesHostileAnswers: each hostile reply below
// crashes, panics or bloats go-sdk's stock lookup stack without the guard.
// Through http.DefaultClient, the stock facilitator gets the guard's error,
// and every consumer of a stock LookupResolver (a SLAP query, FindCompetentHosts
// and the topic Broadcaster's FindInterestedHosts, the path go-overlay-services
// propagation takes) gets an ordinary error and the process lives on.
func TestGuard_StockLookupStackSurvivesHostileAnswers(t *testing.T) {
	ctx := context.Background()
	bigTx, bigBEEF := spendingTx(t, bytes.Repeat([]byte{0xAB}, 600<<10))
	repeats := []*transaction.Transaction{bigTx, bigTx} // 2 x 600 KiB > the 1 MiB expansion budget
	_, smallBEEF := spendingTx(t, []byte("x"))

	for _, h := range []struct {
		name, contentType string
		body              []byte
		chunked           bool
		want              string
	}{
		{"9-byte outpoint count bomb", octetStream, countBomb, false, "binary lookup: outpoint count 4294967296 exceeds capacity of 0 remaining bytes"},
		{"5-byte atomic BEEF prefix", octetStream, []byte{0x00, 0x01, 0x01, 0x01, 0x01}, false, "provided atomic BEEF length (4) is too short"},
		{"MaxInt64 context length", octetStream, hugeContextLenBody(), false, "context[0] length 9223372036854775807 exceeds capacity"},
		{"streamed over the 2 MiB lookup cap", "application/json", freeformOfSize(int(peerhygiene.MaxLookupResponseBytes) + 1), true, "lookup body is over 2097152 bytes"},
		{"declared over the 2 MiB lookup cap", "application/json", freeformOfSize(int(peerhygiene.MaxLookupResponseBytes) + 1), false, "lookup Content-Length 2097153 is over 2097152 bytes"},
		{"null output", "application/json", []byte(`{"type":"output-list","outputs":[null]}`), false, "lookup: output 0 of the answer is null"},
		{"repeated-outpoint expansion", octetStream, binaryAnswer(t, bigBEEF, repeats, 0), false, "re-serialized BEEF exceeds capacity of 1048576 bytes"},
		{"output index past the outputs", "application/json", jsonOutputList(t, smallBEEF, 5), false, "output index 5 is past the transaction's 1 outputs"},
	} {
		t.Run(h.name, func(t *testing.T) {
			url, hits := serveAnswer(t, h.contentType, h.body, h.chunked)

			err := noPanic(t, "facilitator", func() error {
				_, err := (&lookup.HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}).Lookup(ctx, url, slapQuestion)
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "netguard: ") || !strings.Contains(err.Error(), h.want) {
				t.Fatalf("expected the guard to refuse the reply with %q, got: %v", h.want, err)
			}

			err = noPanic(t, "SLAP query", func() error {
				_, err := lookup.NewLookupResolver(&lookup.LookupResolver{SLAPTrackers: []string{url}}).Query(ctx, slapQuestion)
				return err
			})
			if err == nil || err.Error() != "no-successful-responses" {
				t.Fatalf("SLAP query: expected no-successful-responses, got: %v", err)
			}

			err = noPanic(t, "FindCompetentHosts", func() error {
				_, err := lookup.NewLookupResolver(&lookup.LookupResolver{SLAPTrackers: []string{url}}).Query(ctx, shipQuestion)
				return err
			})
			if err == nil || err.Error() != "no-competent-hosts" {
				t.Fatalf("FindCompetentHosts: expected no-competent-hosts, got: %v", err)
			}

			err = noPanic(t, "FindInterestedHosts", func() error {
				resolver := lookup.NewLookupResolver(&lookup.LookupResolver{HostOverrides: map[string][]string{"ls_ship": {url}}})
				b, err := topic.NewBroadcaster([]string{"tm_test"}, &topic.BroadcasterConfig{Resolver: resolver})
				if err != nil {
					t.Fatalf("NewBroadcaster: %v", err)
				}
				_, err = b.FindInterestedHosts(ctx)
				return err
			})
			if err == nil || err.Error() != "no-successful-responses" {
				t.Fatalf("FindInterestedHosts: expected no-successful-responses, got: %v", err)
			}

			if got := hits.Load(); got != 4 {
				t.Fatalf("expected each of the 4 paths to query the host once, got %d requests", got)
			}
		})
	}
}

// TestGuard_ValidatesLookupAnswersBehindRedirects: a host can answer the
// lookup POST with 303 See Other, which the client follows with a GET to
// another path. The final response still reaches go-sdk's facilitator as the
// answer, so the guard must judge it by the request that began the exchange.
func TestGuard_ValidatesLookupAnswersBehindRedirects(t *testing.T) {
	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/lookup" {
			http.Redirect(w, r, "/elsewhere", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", octetStream)
		_, _ = w.Write(countBomb)
	}))
	t.Cleanup(srv.Close)

	err := noPanic(t, "facilitator", func() error {
		_, err := (&lookup.HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}).Lookup(context.Background(), srv.URL, slapQuestion)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "outpoint count 4294967296 exceeds capacity") {
		t.Fatalf("expected the redirected answer to be refused, got: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("expected the lookup and its redirect, got %d requests", hits.Load())
	}
}

type rawReply struct {
	status        int
	contentType   string
	contentLength int64
	body          []byte
}

// postLookup sends a lookup POST through client and reads the raw reply.
func postLookup(t *testing.T, client *http.Client, url string) rawReply {
	t.Helper()
	q, _ := json.Marshal(slapQuestion)
	req, _ := http.NewRequest(http.MethodPost, url+"/lookup", bytes.NewReader(q))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aggregation", "yes")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /lookup: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return rawReply{resp.StatusCode, resp.Header.Get("Content-Type"), resp.ContentLength, body}
}

// TestGuard_PassesHonestLookupAnswersUnchanged: honest binary and JSON
// answers come through http.DefaultClient byte for byte as through an
// unguarded client, with a Content-Length that matches, decode to the same
// answer in the stock facilitator, and satisfy a stock resolver.
func TestGuard_PassesHonestLookupAnswersUnchanged(t *testing.T) {
	ctx := context.Background()
	lock := script.Script{script.OpTRUE}
	parent := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1000})
	child := transaction.NewTransaction()
	child.AddInputFromTx(parent, 0, nil)
	child.Inputs[0].UnlockingScript = &script.Script{}
	child.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
	shared, err := transaction.NewBeefFromTransaction(child)
	if err != nil {
		t.Fatalf("NewBeefFromTransaction: %v", err)
	}
	sharedBytes, err := shared.Bytes()
	if err != nil {
		t.Fatalf("Beef.Bytes: %v", err)
	}
	childBEEF, err := child.BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}
	binary := binaryAnswer(t, sharedBytes, []*transaction.Transaction{parent, child, parent}, 0)

	for _, tc := range []struct {
		name, contentType string
		body              []byte
		chunked           bool
	}{
		{"binary", octetStream, binary, false},
		{"binary streamed", octetStream, binary, true},
		{"JSON output list", "application/json", jsonOutputList(t, childBEEF, 0), false},
		{"JSON freeform streamed", "application/json", []byte(`{"type":"freeform","result":{"hosts":["https://a.example"]}}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := serveAnswer(t, tc.contentType, tc.body, tc.chunked)
			guarded, plain := postLookup(t, http.DefaultClient, url), postLookup(t, &http.Client{}, url)
			if guarded.status != plain.status || guarded.contentType != plain.contentType ||
				!bytes.Equal(guarded.body, tc.body) || !bytes.Equal(plain.body, tc.body) {
				t.Fatalf("reply changed: guarded %d %q %d bytes, unguarded %d %q %d bytes, served %d bytes",
					guarded.status, guarded.contentType, len(guarded.body), plain.status, plain.contentType, len(plain.body), len(tc.body))
			}
			if guarded.contentLength != int64(len(tc.body)) {
				t.Fatalf("guarded Content-Length %d, want %d", guarded.contentLength, len(tc.body))
			}

			want, err := (&lookup.HTTPSOverlayLookupFacilitator{Client: &http.Client{}}).Lookup(ctx, url, slapQuestion)
			if err != nil {
				t.Fatalf("unguarded facilitator: %v", err)
			}
			got, err := (&lookup.HTTPSOverlayLookupFacilitator{Client: http.DefaultClient}).Lookup(ctx, url, slapQuestion)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("guarded facilitator differs: err %v\n got  %+v\n want %+v", err, got, want)
			}
			if _, err := lookup.NewLookupResolver(&lookup.LookupResolver{SLAPTrackers: []string{url}}).Query(ctx, slapQuestion); err != nil {
				t.Fatalf("a stock resolver must accept the answer, got: %v", err)
			}
		})
	}
}

// TestGuard_CoversAPointerCapturedBeforeInstall: a client pointer a library
// took from http.DefaultClient before Install ran is guarded as well.
func TestGuard_CoversAPointerCapturedBeforeInstall(t *testing.T) {
	url, _ := serveAnswer(t, octetStream, countBomb, false)
	err := noPanic(t, "facilitator", func() error {
		_, err := (&lookup.HTTPSOverlayLookupFacilitator{Client: capturedBeforeInstall}).Lookup(context.Background(), url, slapQuestion)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "netguard: rejected lookup answer") {
		t.Fatalf("expected the guard to refuse the reply, got: %v", err)
	}
}
