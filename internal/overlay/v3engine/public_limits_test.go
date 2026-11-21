package v3engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/lookupguard"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

type recordingSyncLimitStorage struct {
	engine.Storage
	limit   uint32
	outputs []*engine.Output
}

func (s *recordingSyncLimitStorage) FindUTXOsForTopic(_ context.Context, _ string, _ float64, limit uint32, _ bool) ([]*engine.Output, error) {
	s.limit = limit
	return s.outputs, nil
}

func TestRequestSyncResponseAllowsFullServerPage(t *testing.T) {
	store := &recordingSyncLimitStorage{outputs: make([]*engine.Output, maxGASPSyncOutputs)}
	for i := range store.outputs {
		var txid chainhash.Hash
		for j := range txid {
			txid[j] = 0xff
		}
		store.outputs[i] = &engine.Output{
			Outpoint: transaction.Outpoint{Txid: txid, Index: math.MaxUint32},
			Score:    math.MaxFloat64,
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/requestSyncResponse", bytes.NewBufferString(`{"version":1,"since":0,"limit":1000}`))
	req.Header.Set("X-BSV-Topic", "tm_test")
	rec := httptest.NewRecorder()
	NewHandlers(engine.NewEngine(&engine.Config{Storage: store})).RequestSyncResponse(rec, req)

	if rec.Code != http.StatusOK || rec.Body.Len() > maxGASPSyncResponseBytes {
		t.Fatalf("full page status %d, size %d", rec.Code, rec.Body.Len())
	}
	var response gasp.InitialResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.UTXOList) != int(maxGASPSyncOutputs) {
		t.Fatalf("response has %d outputs, want %d", len(response.UTXOList), maxGASPSyncOutputs)
	}
}

func TestRequestSyncResponseClampsClientPageLimit(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"since":0,"limit":4294967295}`,
		`{"version":1,"since":0,"limit":0}`,
	} {
		store := &recordingSyncLimitStorage{}
		h := NewHandlers(engine.NewEngine(&engine.Config{Storage: store}))
		req := httptest.NewRequest(http.MethodPost, "/requestSyncResponse", bytes.NewBufferString(body))
		req.Header.Set("X-BSV-Topic", "tm_test")
		rec := httptest.NewRecorder()

		h.RequestSyncResponse(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("body %s: status %d: %s", body, rec.Code, rec.Body.String())
		}
		if store.limit != 1000 {
			t.Fatalf("body %s: storage limit = %d, want 1000", body, store.limit)
		}
	}
}

func TestLookupHandlerBoundsOutputListAndReportsCursor(t *testing.T) {
	outputs := make([]*lookup.OutputListItem, 100)
	for i := range outputs {
		outputs[i] = &lookup.OutputListItem{Beef: make([]byte, 64<<10)}
	}
	eng, _ := newTestEngine(t)
	eng.RegisterLookupService("ls_large", fixedAnswerLookup{answer: &lookup.LookupAnswer{
		Type: lookup.AnswerTypeOutputList, Outputs: outputs,
	}})
	req := httptest.NewRequest(http.MethodPost, "/lookup", bytes.NewBufferString(`{"service":"ls_large","query":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	NewHandlers(eng).Lookup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if int64(rec.Body.Len()) > routeguard.LookupAllowance {
		t.Fatalf("response is %d bytes, cap is %d", rec.Body.Len(), routeguard.LookupAllowance)
	}
	if rec.Header().Get("X-Overlay-Truncated") != "true" || rec.Header().Get("X-Overlay-Cursor") == "" {
		t.Fatalf("missing truncation cursor: %v", rec.Header())
	}
}

func TestPerOutputFallbackBoundsEncodedReply(t *testing.T) {
	outputs := []answerOutput{{item: &lookup.OutputListItem{Beef: bytes.Repeat([]byte{255}, 3<<20)}}}
	rec := httptest.NewRecorder()
	if err := writePerOutputAnswer(rec, outputs); err == nil {
		t.Fatal("oversized per-output fallback was accepted")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("wrote %d bytes before refusing oversized fallback", rec.Body.Len())
	}
}

func TestAggregatedAnswerServesThreeMiBBEEF(t *testing.T) {
	tx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: opReturn(3 << 20), Satoshis: 1})
	beef := atomicBEEF(t, tx)
	if len(beef) < 3<<20 {
		t.Fatalf("BEEF is %d bytes, want at least 3 MiB", len(beef))
	}
	rec := httptest.NewRecorder()
	err := writeAggregatedAnswer(rec, &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: []*lookup.OutputListItem{{Beef: beef}}})
	if err != nil {
		t.Fatalf("write binary answer: %v", err)
	}
	if rec.Code != http.StatusOK || int64(rec.Body.Len()) > routeguard.LookupAllowance {
		t.Fatalf("binary answer status %d, size %d", rec.Code, rec.Body.Len())
	}
	page, err := capAggregatedAnswer(lookupguard.Result{Answer: &lookup.LookupAnswer{
		Type: lookup.AnswerTypeOutputList, Outputs: []*lookup.OutputListItem{{Beef: beef}},
	}}, 0)
	if err != nil || page.Truncated || len(page.Answer.Outputs) != 1 {
		t.Fatalf("binary page = %#v, error %v", page, err)
	}
}

func TestAggregatedAnswerOmitsBEEFOverRouteAllowance(t *testing.T) {
	tx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: opReturn(9 << 20), Satoshis: 1})
	page, err := capAggregatedAnswer(lookupguard.Result{Answer: &lookup.LookupAnswer{
		Type: lookup.AnswerTypeOutputList, Outputs: []*lookup.OutputListItem{{Beef: atomicBEEF(t, tx)}},
	}}, 0)
	if err != nil {
		t.Fatalf("cap binary answer: %v", err)
	}
	if page.Truncated || page.Omitted != 1 || len(page.Answer.Outputs) != 0 {
		t.Fatalf("binary page = %#v", page)
	}
}

func typeScriptSHIPBody(beef, offChain []byte) []byte {
	var prefix []byte
	switch n := len(beef); {
	case n < 0xfd:
		prefix = []byte{byte(n)}
	case n <= 0xffff:
		prefix = make([]byte, 3)
		prefix[0] = 0xfd
		binary.LittleEndian.PutUint16(prefix[1:], uint16(n))
	case uint64(n) <= 0xffffffff:
		prefix = make([]byte, 5)
		prefix[0] = 0xfe
		binary.LittleEndian.PutUint32(prefix[1:], uint32(n))
	default:
		prefix = make([]byte, 9)
		prefix[0] = 0xff
		binary.LittleEndian.PutUint64(prefix[1:], uint64(n))
	}
	body := append(prefix, beef...)
	return append(body, offChain...)
}

func TestSubmitHandlerAcceptsTypeScriptSHIPFraming(t *testing.T) {
	eng, _ := newTestEngine(t)
	const hashHex = "3232323232323232323232323232323232323232323232323232323232323232"
	tagged := buildUHRPTaggedBEEF(t, hashHex, "https://example.test/ship", "image/png", true)
	body := typeScriptSHIPBody(tagged.Beef, []byte{0xde, 0xad, 0xbe, 0xef})
	req := httptest.NewRequest(http.MethodPost, "/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Topics", topics.UHRPTopicName)
	req.Header.Set("x-includes-off-chain-values", "true")
	rec := httptest.NewRecorder()

	NewHandlers(eng).Submit(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var steak overlay.Steak
	if err := json.Unmarshal(rec.Body.Bytes(), &steak); err != nil {
		t.Fatalf("decode STEAK: %v", err)
	}
	if inst := steak[topics.UHRPTopicName]; inst == nil || len(inst.OutputsToAdmit) != 1 {
		t.Fatalf("unexpected STEAK: %+v", steak)
	}
}

func TestSplitOffChainValuesAcceptsEarlierPrefixOrder(t *testing.T) {
	beef := []byte{0x01, 0x00, 0xbe, 0xef, 0x00}
	offChain := []byte{0xde, 0xad, 0xbe, 0xef}
	body := append([]byte{byte(len(offChain))}, offChain...)
	body = append(body, beef...)
	gotBEEF, gotOffChain, err := splitOffChainValues(body, "true")
	if err != nil {
		t.Fatalf("split earlier framing: %v", err)
	}
	if !bytes.Equal(gotBEEF, beef) || !bytes.Equal(gotOffChain, offChain) {
		t.Fatalf("split earlier framing = (%x, %x), want (%x, %x)", gotBEEF, gotOffChain, beef, offChain)
	}
}
