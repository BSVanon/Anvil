package lookups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

const ordLockBuyItemPrefix = "lk_ordlockbuy:item:" // lk_ordlockbuy:item:<txid>:<vout> → entry JSON

const (
	ordLockBuyDefaultLimit = 100
	ordLockBuyMaxLimit     = 500
)

// OrdLockBuyLookupService implements engine.LookupService for the
// OrdLockBuy buy-side vault topic.
type OrdLockBuyLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewOrdLockBuyLookupService constructs an OrdLockBuy-vaults lookup
// backed by the given LevelDB handle.
func NewOrdLockBuyLookupService(db *leveldb.DB) *OrdLockBuyLookupService {
	return &OrdLockBuyLookupService{
		db:   db,
		docs: "OrdLockBuy Vaults Lookup: query active buy-side vaults that hold the buyer's locked BSV against a target listing. Filter by tokenId, tick, cancelAddress, or outpoint; paginate via limit/offset; default sort is admittedAt descending.",
		meta: &overlay.MetaData{
			Name:        topics.OrdLockBuyLookupServiceName,
			Description: "OrdLockBuy vault queries (BSV-20/21)",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion.
var _ engine.LookupService = (*OrdLockBuyLookupService)(nil)

// --- event handlers --------------------------------------------------------

// BackfillFromLegacyMetadata populates this service's lk_ordlockbuy
// index for a single legacy AdmittedOutput. Used by W-4 phase B
// migration. metadata is a JSON-encoded topics.OrdLockBuyEntry. See
// the UHRP backfill doc-comment for the canonical /lookup BEEF-empty
// limitation that applies equally here.
func (s *OrdLockBuyLookupService) BackfillFromLegacyMetadata(outpoint *transaction.Outpoint, metadata json.RawMessage) error {
	if outpoint == nil {
		return errors.New("ordlock-buy backfill: nil outpoint")
	}
	if len(metadata) == 0 {
		return errors.New("ordlock-buy backfill: empty metadata")
	}
	var entry topics.OrdLockBuyEntry
	if err := json.Unmarshal(metadata, &entry); err != nil {
		return fmt.Errorf("ordlock-buy backfill: decode metadata: %w", err)
	}
	body, err := json.Marshal(&entry)
	if err != nil {
		return fmt.Errorf("ordlock-buy backfill: marshal entry: %w", err)
	}
	if err := s.db.Put(itemKey(ordLockBuyItemPrefix, &outpoint.Txid, outpoint.Index), body, nil); err != nil {
		return fmt.Errorf("ordlock-buy backfill: write item: %w", err)
	}
	return nil
}

// OutputAdmittedByTopic parses the OrdLockBuy vault covenant via
// topics.ParseOrdLockBuyScript and stores the entry in the local index.
func (s *OrdLockBuyLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.OrdLockBuyTopicName {
		return nil
	}
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("ordlock-buy lookup: %w", err)
	}
	if int(payload.OutputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("ordlock-buy lookup: output index %d out of range for tx %s", payload.OutputIndex, focusTxid.String())
	}
	out := tx.Outputs[payload.OutputIndex]
	if out.LockingScript == nil {
		return nil
	}
	entry := topics.ParseOrdLockBuyScript(out.LockingScript.Bytes())
	if entry == nil {
		return nil
	}
	entry.Outpoint = fmt.Sprintf("%s_%d", focusTxid.String(), payload.OutputIndex)
	entry.AdmittedAt = time.Now().UTC().Format(time.RFC3339)

	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ordlock-buy lookup: marshal entry: %w", err)
	}
	if err := s.db.Put(itemKey(ordLockBuyItemPrefix, focusTxid, payload.OutputIndex), body, nil); err != nil {
		return fmt.Errorf("ordlock-buy lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the vault from the local index.
func (s *OrdLockBuyLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.OrdLockBuyTopicName || payload.Outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(ordLockBuyItemPrefix, &payload.Outpoint.Txid, payload.Outpoint.Index))
	return err
}

// OutputNoLongerRetainedInHistory is treated identically to OutputSpent.
func (s *OrdLockBuyLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.OrdLockBuyTopicName || outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(ordLockBuyItemPrefix, &outpoint.Txid, outpoint.Index))
	return err
}

// OutputEvicted removes the outpoint regardless of topic.
func (s *OrdLockBuyLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(ordLockBuyItemPrefix, &outpoint.Txid, outpoint.Index))
	return err
}

// OutputBlockHeightUpdated is a no-op — vault queries are sorted by
// admittedAt, not block height.
func (s *OrdLockBuyLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- query path ------------------------------------------------------------

// Lookup answers an OrdLockBuy query. Filters by tokenId / tick /
// cancelAddress / outpoint, sorts admittedAt-descending, paginates with
// limit+offset, returns formulas.
func (s *OrdLockBuyLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("ordlock-buy lookup: nil question")
	}
	if question.Service != topics.OrdLockBuyLookupServiceName {
		return nil, fmt.Errorf("ordlock-buy lookup: service %q not supported", question.Service)
	}

	var q topics.OrdLockBuyQuery
	if err := jsonUnmarshalQuery(question.Query, &q); err != nil {
		return nil, fmt.Errorf("ordlock-buy lookup: %w", err)
	}

	cancelPkhFilter, err := topics.NormalizeCancelFilter(q.CancelAddress)
	if err != nil {
		return nil, err
	}
	tickFilter := strings.ToUpper(strings.TrimSpace(q.Tick))
	outpointFilter := strings.TrimSpace(q.Outpoint)

	type pair struct {
		op    *transaction.Outpoint
		entry topics.OrdLockBuyEntry
	}
	var matches []pair
	err = scanPrefix(s.db, []byte(ordLockBuyItemPrefix), func(key, value []byte) error {
		var entry topics.OrdLockBuyEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return nil
		}
		if !matchesOrdLockBuyEntry(entry, q.TokenId, tickFilter, cancelPkhFilter, outpointFilter) {
			return nil
		}
		op, ok := decodeItemKeyOutpoint(key, ordLockBuyItemPrefix)
		if !ok {
			return nil
		}
		matches = append(matches, pair{op: op, entry: entry})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ordlock-buy lookup: scan: %w", err)
	}

	sort.SliceStable(matches, func(a, b int) bool {
		return matches[a].entry.AdmittedAt > matches[b].entry.AdmittedAt
	})

	page := applyPagination(matches, q.Limit, q.Offset, ordLockBuyDefaultLimit, ordLockBuyMaxLimit)
	outpoints := make([]*transaction.Outpoint, 0, len(page))
	for _, p := range page {
		outpoints = append(outpoints, p.op)
	}
	return formulaList(outpoints), nil
}

// GetDocumentation returns the human-readable description.
func (s *OrdLockBuyLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the typed canonical metadata block.
func (s *OrdLockBuyLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// matchesOrdLockBuyEntry applies the filter rules. Mirrors the existing
// topics.matchesOrdLockBuyQuery: tokenId + tick are mutually exclusive,
// outpoint short-circuits when supplied, cancelPkh is always applied if
// present.
func matchesOrdLockBuyEntry(entry topics.OrdLockBuyEntry, tokenId, tickUpper, cancelPkhFilterLower, outpointFilter string) bool {
	if outpointFilter != "" {
		if !strings.EqualFold(entry.Outpoint, outpointFilter) {
			return false
		}
	}
	switch {
	case tokenId != "":
		if !strings.EqualFold(entry.TokenId, tokenId) {
			return false
		}
	case tickUpper != "":
		if entry.Tick != tickUpper {
			return false
		}
	}
	if cancelPkhFilterLower != "" {
		if !strings.EqualFold(entry.CancelPkhHex, cancelPkhFilterLower) {
			return false
		}
	}
	return true
}
