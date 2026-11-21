// Package lookupguard bounds public lookup result construction.
package lookupguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

const (
	// CursorHeader resumes a truncated result at the next formula or output.
	CursorHeader = "X-Overlay-Cursor"
	// TruncatedHeader reports that another bounded page may be requested.
	TruncatedHeader = "X-Overlay-Truncated"
	// OmittedHeader reports outputs too large for a response page.
	OmittedHeader = "X-Overlay-Omitted"
)

type stateKey struct{}

type queryState struct {
	cursor    int
	applied   bool
	truncated bool
	next      int
}

// Result carries a bounded answer and its pagination state.
type Result struct {
	Answer    *lookup.LookupAnswer
	Truncated bool
	Next      int
	Omitted   int
}

// ParseCursor reads the optional result offset supplied by a previous page.
func ParseCursor(r *http.Request) (int, error) {
	raw := r.Header.Get(CursorHeader)
	if raw == "" {
		return 0, nil
	}
	cursor, err := strconv.Atoi(raw)
	if err != nil || cursor < 0 {
		return 0, errors.New("invalid lookup cursor")
	}
	return cursor, nil
}

// WriteHeaders reports pagination state without changing either response body.
func WriteHeaders(w http.ResponseWriter, result Result) {
	if result.Omitted > 0 {
		w.Header().Set(OmittedHeader, strconv.Itoa(result.Omitted))
	}
	if !result.Truncated {
		return
	}
	w.Header().Set(TruncatedHeader, "true")
	w.Header().Set(CursorHeader, strconv.Itoa(result.Next))
}

// Pager lets an index scan stop after one bounded page of matching records.
// The extra match is observed only to report truncation; it is not retained.
type Pager struct {
	state    *queryState
	cursor   int
	seen     int
	accepted int
}

// NewPager returns a count limiter for one service index scan.
func NewPager(ctx context.Context) *Pager {
	state, _ := ctx.Value(stateKey{}).(*queryState)
	p := &Pager{state: state}
	if state != nil {
		state.applied = true
		p.cursor = state.cursor
	}
	return p
}

// Take reports whether the current matching record belongs to this page and
// whether the scan can stop. Call it only after all query filters match.
func (p *Pager) Take() (take, stop bool) {
	p.seen++
	if p.seen <= p.cursor {
		return false, false
	}
	if p.accepted < peerhygiene.MaxLookupOutputs {
		p.accepted++
		return true, false
	}
	if p.state != nil {
		p.state.truncated = true
		p.state.next = p.cursor + p.accepted
	}
	return false, true
}

// Lookup executes a service lookup and hydrates only the bounded page.
func Lookup(ctx context.Context, eng *engine.Engine, question *lookup.LookupQuestion, cursor int) (Result, error) {
	return LookupForWire(ctx, eng, question, cursor, false)
}

// LookupForWire applies the encoded JSON cap unless binary aggregation was
// requested. Binary replies are checked after aggregation.
func LookupForWire(ctx context.Context, eng *engine.Engine, question *lookup.LookupQuestion, cursor int, binary bool) (Result, error) {
	service, ok := eng.GetLookupService(question.Service)
	if !ok {
		return Result{}, engine.ErrUnknownTopic
	}
	state := &queryState{cursor: cursor}
	ctx = context.WithValue(ctx, stateKey{}, state)
	answer, err := service.Lookup(ctx, question)
	if err != nil {
		return Result{}, err
	}
	if answer == nil {
		answer = &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList}
	}

	var result Result
	switch answer.Type {
	case lookup.AnswerTypeFormula:
		result, err = hydrate(ctx, eng, answer.Formulas, cursorIfNeeded(state), !binary)
	case lookup.AnswerTypeOutputList:
		result, err = capOutputs(answer.Outputs, cursorIfNeeded(state), !binary)
	case lookup.AnswerTypeFreeform:
		result = Result{Answer: answer}
		_, err = boundedJSON(answer)
	default:
		err = fmt.Errorf("unsupported lookup answer type %q", answer.Type)
	}
	if err != nil {
		return Result{}, err
	}
	if state.truncated && !result.Truncated && len(result.Answer.Outputs) > 0 {
		result.Truncated = true
		result.Next = state.next
	}
	return result, nil
}

func cursorIfNeeded(state *queryState) int {
	if state.applied {
		return 0
	}
	return state.cursor
}

func hydrate(ctx context.Context, eng *engine.Engine, formulas []lookup.LookupFormula, cursor int, limitJSON bool) (Result, error) {
	outputs := make([]*lookup.OutputListItem, 0, min(len(formulas), peerhygiene.MaxLookupOutputs))
	page := newOutputPage(limitJSON)
	omitted := 0
	for i := cursor; i < len(formulas); i++ {
		if len(outputs) == peerhygiene.MaxLookupOutputs {
			return Result{Answer: outputAnswer(outputs), Truncated: true, Next: i, Omitted: omitted}, nil
		}
		item, err := hydrateOne(ctx, eng, &formulas[i])
		if err != nil {
			return Result{}, err
		}
		if item == nil {
			continue
		}
		if !page.fits(item) {
			omitted++
			continue
		}
		if !page.add(item) {
			return Result{Answer: outputAnswer(outputs), Truncated: true, Next: i, Omitted: omitted}, nil
		}
		outputs = append(outputs, item)
	}
	return Result{Answer: outputAnswer(outputs), Omitted: omitted}, nil
}

func hydrateOne(ctx context.Context, eng *engine.Engine, formula *lookup.LookupFormula) (*lookup.OutputListItem, error) {
	output, err := eng.Storage.FindOutput(ctx, formula.Outpoint, nil, nil, true)
	if err != nil || output == nil || output.Beef == nil {
		return nil, err
	}
	if err := eng.Storage.LoadAncillaryBeef(ctx, output); err != nil {
		return nil, err
	}
	hydrated, err := eng.GetUTXOHistory(ctx, output, formula.History, 0)
	if err != nil || hydrated == nil || hydrated.Beef == nil {
		return nil, err
	}
	beef, err := hydrated.Beef.AtomicBytes(&hydrated.Outpoint.Txid)
	if err != nil {
		return nil, err
	}
	return &lookup.OutputListItem{Beef: beef, OutputIndex: hydrated.Outpoint.Index}, nil
}

func capOutputs(source []*lookup.OutputListItem, cursor int, limitJSON bool) (Result, error) {
	outputs := make([]*lookup.OutputListItem, 0, min(len(source), peerhygiene.MaxLookupOutputs))
	page := newOutputPage(limitJSON)
	omitted := 0
	for i := cursor; i < len(source); i++ {
		if len(outputs) == peerhygiene.MaxLookupOutputs {
			return Result{Answer: outputAnswer(outputs), Truncated: true, Next: i, Omitted: omitted}, nil
		}
		if !page.fits(source[i]) {
			omitted++
			continue
		}
		if !page.add(source[i]) {
			return Result{Answer: outputAnswer(outputs), Truncated: true, Next: i, Omitted: omitted}, nil
		}
		outputs = append(outputs, source[i])
	}
	return Result{Answer: outputAnswer(outputs), Omitted: omitted}, nil
}

type outputPage struct {
	wireBytes  int64
	items      int
	limitJSON  bool
	cachedItem *lookup.OutputListItem
	cachedSize int64
	cached     bool
}

func newOutputPage(limitJSON bool) *outputPage {
	return &outputPage{
		wireBytes: int64(len(`{"type":"output-list","outputs":[]}`)),
		limitJSON: limitJSON,
	}
}

func (p *outputPage) add(item *lookup.OutputListItem) bool {
	if !p.limitJSON {
		p.items++
		return true
	}
	encodedSize, ok := p.encodedItemSize(item)
	p.cachedItem = nil
	p.cached = false
	if !ok {
		return false
	}
	wireBytes := p.wireBytes + encodedSize
	if p.items > 0 {
		wireBytes++
	}
	if wireBytes > routeguard.LookupAllowance {
		return false
	}
	p.wireBytes = wireBytes
	p.items++
	return true
}

func (p *outputPage) fits(item *lookup.OutputListItem) bool {
	if !p.limitJSON {
		return true
	}
	encodedSize, ok := p.encodedItemSize(item)
	if !ok {
		return false
	}
	wireBytes := int64(len(`{"type":"output-list","outputs":[]}`)) + encodedSize
	return wireBytes <= routeguard.LookupAllowance
}

func (p *outputPage) encodedItemSize(item *lookup.OutputListItem) (int64, bool) {
	if p.cached && p.cachedItem == item {
		return p.cachedSize, true
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		return 0, false
	}
	p.cachedItem = item
	p.cachedSize = int64(len(encoded))
	p.cached = true
	return p.cachedSize, true
}

func outputAnswer(outputs []*lookup.OutputListItem) *lookup.LookupAnswer {
	return &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: outputs}
}

func boundedJSON(answer *lookup.LookupAnswer) ([]byte, error) {
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	if int64(len(encoded)) > routeguard.LookupAllowance {
		return nil, fmt.Errorf("lookup response is over %d bytes", routeguard.LookupAllowance)
	}
	return encoded, nil
}
