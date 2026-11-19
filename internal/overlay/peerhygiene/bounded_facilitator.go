package peerhygiene

// Attribution: BoundedFacilitator.Lookup's HTTP exchange and
// parseBinaryLookupAnswer's wire format are ported from go-sdk v1.7.7
// overlay/lookup/facilitator.go (HTTPSOverlayLookupFacilitator and its
// parseBinaryLookupAnswer), Copyright the go-sdk authors, used under the Open
// BSV License (see the go-sdk LICENSE file). Anvil adds the response-size
// cap, the bounds on wire-supplied counts and lengths, the output, BEEF and
// decode-cost caps, null-output rejection, the decoding slot and the panic
// guard.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// minBinaryOutpointBytes is the smallest encoding of one outpoint entry in a
// binary answer: a 32-byte txid plus a 1-byte outputIndex varint and a 1-byte
// contextLen varint.
const minBinaryOutpointBytes = 32 + 1 + 1

// binaryContentType marks the aggregated binary answer format. The
// facilitators match it exactly.
const binaryContentType = "application/octet-stream"

// LookupReadTimeout bounds how long reading one reply may hold a decoding
// slot, so a peer that trickles its reply cannot keep the slot. It is
// go-sdk's own SLAP tracker and SHIP query timeout.
const LookupReadTimeout = 30 * time.Second

// ErrLookupResponseTooLarge is returned when a peer's reply exceeds the
// response cap.
var ErrLookupResponseTooLarge = errors.New("peerhygiene: lookup response exceeds size cap")

// newBeefFromBytes is transaction.NewBeefFromBytes, held in a variable so a
// test can make decoding panic and check that the panic guard turns the panic
// into an error.
var newBeefFromBytes = transaction.NewBeefFromBytes

// BoundedFacilitator is a lookup.Facilitator that speaks the same wire protocol
// as go-sdk's HTTPSOverlayLookupFacilitator: it POSTs the JSON question to
// {url}/lookup with X-Aggregation: yes and accepts a JSON answer or an
// application/octet-stream aggregated binary answer, decoded into the same
// LookupAnswer shape. Unlike the upstream facilitator it treats the reply as
// untrusted. It reads at most MaxBytes, it checks every wire-supplied count
// and length against the bytes actually present before allocating, it holds
// the answer to the caps in budget.go, it decodes under one of the
// LookupSlots decoding slots, and it turns any panic while decoding into an
// error. A panic would otherwise be fatal: go-sdk's LookupResolver calls the
// facilitator in a goroutine of its own, with no recover.
type BoundedFacilitator struct {
	// Client sends the request. Nil uses http.DefaultClient.
	Client util.HTTPClient
	// MaxBytes caps the response body. Zero or less uses
	// MaxLookupResponseBytes.
	MaxBytes int64
}

var _ lookup.Facilitator = (*BoundedFacilitator)(nil)

// Lookup sends question to url's /lookup endpoint and decodes the answer.
func (f *BoundedFacilitator) Lookup(ctx context.Context, url string, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	q, err := json.Marshal(question)
	if err != nil {
		return nil, err
	}
	ctx, claim := withSlotClaim(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/lookup", bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aggregation", "yes")

	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	maxBytes := f.maxBytes()
	switch {
	case resp.StatusCode != http.StatusOK:
		_ = resp.Body.Close()
		return nil, &util.HTTPError{StatusCode: resp.StatusCode, Err: errors.New("lookup failed")}
	case resp.ContentLength > maxBytes:
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: Content-Length %d is over %d bytes", ErrLookupResponseTooLarge, resp.ContentLength, maxBytes)
	case claim.held.Load():
		// Through http.DefaultClient the netguard transport has read and
		// checked the answer already, under its own read permit and then a
		// slot, which Close returns.
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		if int64(len(body)) > maxBytes {
			return nil, fmt.Errorf("%w: body is over %d bytes", ErrLookupResponseTooLarge, maxBytes)
		}
		return decodeLookupAnswer(resp.Header.Get("Content-Type"), body)
	}
	// Otherwise the answer is read first, under one of the process-wide read
	// permits and within its time and rate limits, and only then decoded
	// under a slot taken here, so a peer that sends its reply slowly holds a
	// permit, of which there are many, never a slot.
	releaseRead, err := bodyread.Lookups.Acquire(ctx)
	if err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %w", ErrNoLookupSlot, err)
	}
	body, err := bodyread.Read(resp.Body, resp.ContentLength, bodyread.Limits{
		Max: maxBytes, Timeout: LookupReadTimeout, MinRate: bodyread.MinReadRate, Grace: bodyread.ReadGrace,
	})
	if err != nil {
		releaseRead()
		if errors.Is(err, bodyread.ErrTooLarge) {
			return nil, fmt.Errorf("%w: body is over %d bytes", ErrLookupResponseTooLarge, maxBytes)
		}
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	release, err := AcquireLookupSlot(ctx)
	releaseRead()
	if err != nil {
		return nil, err
	}
	defer release()
	return decodeLookupAnswer(resp.Header.Get("Content-Type"), body)
}

func (f *BoundedFacilitator) maxBytes() int64 {
	if f.MaxBytes <= 0 {
		return MaxLookupResponseBytes
	}
	return f.MaxBytes
}

// decodeLookupAnswer decodes a reply body by its Content-Type, as the
// upstream facilitator does (exact match on application/octet-stream,
// otherwise JSON), and holds the answer to the caps in budget.go. Any panic
// while decoding becomes an error.
func decodeLookupAnswer(contentType string, body []byte) (answer *lookup.LookupAnswer, err error) {
	defer func() {
		if r := recover(); r != nil {
			answer = nil
			err = fmt.Errorf("lookup: decoding answer panicked: %v", r)
		}
	}()
	if contentType == binaryContentType {
		return parseBinaryLookupAnswer(body)
	}
	if cost := jsonCost(body); cost > MaxJSONDecodeCost {
		return nil, fmt.Errorf("lookup: decoding the JSON answer could cost %d bytes, over the %d-byte cap", cost, MaxJSONDecodeCost)
	}
	answer = &lookup.LookupAnswer{}
	if err := json.Unmarshal(body, answer); err != nil {
		return nil, err
	}
	// go-sdk's LookupResolver dereferences every output without a nil check,
	// so a JSON answer of `"outputs":[null]` would crash it.
	for i, out := range answer.Outputs {
		if out == nil {
			return nil, fmt.Errorf("lookup: output %d of the answer is null", i)
		}
	}
	if n := len(answer.Outputs); n > MaxLookupOutputs {
		return nil, fmt.Errorf("lookup: the answer lists %d outputs, over the %d-output cap", n, MaxLookupOutputs)
	}
	var beefBytes int64
	for i, out := range answer.Outputs {
		if beefBytes += int64(len(out.Beef)); beefBytes > MaxAnswerBEEFBytes {
			return nil, fmt.Errorf("lookup: the outputs' BEEF exceeds capacity of %d bytes", MaxAnswerBEEFBytes)
		}
		if cost := beefCost(out.Beef); cost > MaxBEEFParseCost {
			return nil, fmt.Errorf("lookup: parsing output %d's BEEF could cost %d bytes, over the %d-byte cap", i, cost, MaxBEEFParseCost)
		}
	}
	return answer, nil
}

// parseBinaryLookupAnswer decodes the aggregated binary output-list format
// overlay nodes return for X-Aggregation: yes:
//
//	VarInt          nOutpoints
//	[nOutpoints]×{
//	  [32]byte      txid (the display-order txid's bytes, as ts-stack writes them)
//	  VarInt        outputIndex
//	  VarInt        contextLen
//	  [contextLen]  context (omitted when contextLen == 0)
//	}
//	[]byte          BEEF (shared; contains all referenced transactions)
//
// Each output gets its own V1 BEEF of the referenced transaction and its
// ancestry, as upstream produces, and context is skipped, as upstream drops it.
// Outputs that name the same transaction share one serialization here, but
// every output counts against MaxAnswerBEEFBytes, repeats included: upstream
// re-serializes once per output, and ValidateLookupAnswer relies on this
// budget to bound what upstream allocates for a reply it lets through.
func parseBinaryLookupAnswer(data []byte) (*lookup.LookupAnswer, error) {
	r := util.NewReader(data)
	remaining := func() uint64 { return uint64(len(r.Data) - r.Pos) } //nolint:gosec // Pos never passes len(Data)

	nOutpoints, err := r.ReadVarInt()
	if err != nil {
		return nil, fmt.Errorf("binary lookup: reading outpoint count: %w", err)
	}
	if nOutpoints > remaining()/minBinaryOutpointBytes {
		return nil, fmt.Errorf("binary lookup: outpoint count %d exceeds capacity of %d remaining bytes", nOutpoints, remaining())
	}
	if nOutpoints > MaxLookupOutputs {
		return nil, fmt.Errorf("binary lookup: the answer lists %d outputs, over the %d-output cap", nOutpoints, MaxLookupOutputs)
	}

	type outpointMeta struct {
		txid        string
		outputIndex uint32
	}
	metas := make([]outpointMeta, 0, nOutpoints)
	for i := uint64(0); i < nOutpoints; i++ {
		txidBytes, err := r.ReadBytes(32)
		if err != nil {
			return nil, fmt.Errorf("binary lookup: reading txid[%d]: %w", i, err)
		}
		outputIndex, err := r.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("binary lookup: reading outputIndex[%d]: %w", i, err)
		}
		if outputIndex > math.MaxUint32 {
			return nil, fmt.Errorf("binary lookup: outputIndex[%d] %d is out of range", i, outputIndex)
		}
		contextLen, err := r.ReadVarInt()
		if err != nil {
			return nil, fmt.Errorf("binary lookup: reading contextLen[%d]: %w", i, err)
		}
		if contextLen > remaining() {
			return nil, fmt.Errorf("binary lookup: context[%d] length %d exceeds capacity of %d remaining bytes", i, contextLen, remaining())
		}
		r.Pos += int(contextLen) //nolint:gosec // bounded by remaining() just above
		metas = append(metas, outpointMeta{
			txid:        hex.EncodeToString(txidBytes),
			outputIndex: uint32(outputIndex),
		})
	}

	// The remaining bytes are the shared BEEF holding every referenced
	// transaction. Price it before anything parses it: upstream parses it
	// again, and every output's re-serialization is a subset of it.
	shared := r.Data[r.Pos:]
	if cost := beefCost(shared); cost > MaxBEEFParseCost {
		return nil, fmt.Errorf("binary lookup: parsing the BEEF could cost %d bytes, over the %d-byte cap", cost, MaxBEEFParseCost)
	}
	beef, err := newBeefFromBytes(shared)
	if err != nil {
		return nil, fmt.Errorf("binary lookup: parsing BEEF: %w", err)
	}
	splitProofs(beef)

	type rebuilt struct {
		beef      []byte
		parseWork uint64
	}
	outputs := make([]*lookup.OutputListItem, 0, len(metas))
	serialized := make(map[string]rebuilt, len(metas))
	budget := &combineBudget{max: MaxAnswerCombineWork}
	var expanded int64
	for _, m := range metas {
		out, ok := serialized[m.txid]
		if !ok {
			txid, err := chainhash.NewHashFromHex(m.txid)
			if err != nil {
				return nil, fmt.Errorf("binary lookup: txid %s: %w", m.txid, err)
			}
			tx := beef.FindTransactionByHash(txid)
			if tx == nil {
				return nil, fmt.Errorf("binary lookup: txid %s not found in BEEF", m.txid)
			}
			if out.beef, out.parseWork, err = outputBEEF(tx, *txid, budget); err != nil {
				return nil, fmt.Errorf("binary lookup: re-serializing BEEF for txid %s: %w", m.txid, err)
			}
			serialized[m.txid] = out
		}
		if expanded += int64(len(out.beef)); expanded > MaxAnswerBEEFBytes {
			return nil, fmt.Errorf("binary lookup: re-serialized BEEF exceeds capacity of %d bytes", MaxAnswerBEEFBytes)
		}
		// Every output is parsed again downstream, repeats included.
		if err := budget.charge(out.parseWork); err != nil {
			return nil, fmt.Errorf("binary lookup: %w", err)
		}
		outputs = append(outputs, &lookup.OutputListItem{Beef: out.beef, OutputIndex: m.outputIndex})
	}
	return &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: outputs}, nil
}
