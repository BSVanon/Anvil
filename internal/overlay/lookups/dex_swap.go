package lookups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

const dexSwapItemPrefix = "lk_dexswap:item:" // lk_dexswap:item:<txid>:<vout> → item JSON

// dexSwapItem is the per-output record kept by the DEX-swap lookup. The
// JSON shape mirrors topics.DEXSwapEntry minus the offer-vout (which is
// recoverable from the storage key) plus an AdmittedAt timestamp.
type dexSwapItem struct {
	Maker        string          `json:"maker"`
	Offering     json.RawMessage `json:"offering"`
	Requesting   json.RawMessage `json:"requesting"`
	RefundHeight int             `json:"refundHeight"`
	AdmittedAt   int64           `json:"admitted_at"`
}

// DEXSwapLookupService implements engine.LookupService for the BRC-79
// DEX-swap topic.
type DEXSwapLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewDEXSwapLookupService constructs a DEX-swap lookup backed by the
// given LevelDB handle.
func NewDEXSwapLookupService(db *leveldb.DB) *DEXSwapLookupService {
	return &DEXSwapLookupService{
		db:   db,
		docs: "DEX Swap Lookup: query active peer-to-peer swap offers. Filter by token pair, maker, or list all.",
		meta: &overlay.MetaData{
			Name:        topics.DEXSwapLookupServiceName,
			Description: "BRC-79 DEX-swap offer queries",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion.
var _ engine.LookupService = (*DEXSwapLookupService)(nil)

// --- event handlers --------------------------------------------------------

// BackfillFromLegacyMetadata populates this service's lk_dexswap
// index for a single legacy AdmittedOutput. Used by W-4 phase B
// migration. metadata is a JSON-encoded topics.DEXSwapEntry. See the
// UHRP backfill doc-comment for the canonical /lookup BEEF-empty
// limitation that applies equally here.
func (s *DEXSwapLookupService) BackfillFromLegacyMetadata(outpoint *transaction.Outpoint, metadata json.RawMessage) error {
	if outpoint == nil {
		return errors.New("dex-swap backfill: nil outpoint")
	}
	if len(metadata) == 0 {
		return errors.New("dex-swap backfill: empty metadata")
	}
	var entry topics.DEXSwapEntry
	if err := json.Unmarshal(metadata, &entry); err != nil {
		return fmt.Errorf("dex-swap backfill: decode metadata: %w", err)
	}
	item := dexSwapItem{
		Maker:        entry.Maker,
		Offering:     entry.Offering,
		Requesting:   entry.Requesting,
		RefundHeight: entry.RefundHeight,
		AdmittedAt:   time.Now().Unix(),
	}
	body, err := json.Marshal(&item)
	if err != nil {
		return fmt.Errorf("dex-swap backfill: marshal item: %w", err)
	}
	if err := s.db.Put(itemKey(dexSwapItemPrefix, &outpoint.Txid, outpoint.Index), body, nil); err != nil {
		return fmt.Errorf("dex-swap backfill: write item: %w", err)
	}
	return nil
}

// OutputAdmittedByTopic finds the DEX-swap metadata output associated with
// the admitted offer UTXO and stores the parsed entry in the local index.
//
// The topic manager admits the offer output at vout N and the metadata
// OP_RETURN sits at vout N+1 (enforced by topics.DEXSwapTopicManager.Admit
// rule 2). We mirror that lookup direction: scan the tx for metadata
// outputs whose OfferVout points back at payload.OutputIndex.
func (s *DEXSwapLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.DEXSwapTopicName {
		return nil
	}
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("dex-swap lookup: %w", err)
	}

	entry := findDEXSwapEntryForOffer(tx, int(payload.OutputIndex))
	if entry == nil {
		// No metadata output points at this offer — be defensive and
		// skip rather than fail the whole admission.
		return nil
	}

	item := dexSwapItem{
		Maker:        entry.Maker,
		Offering:     entry.Offering,
		Requesting:   entry.Requesting,
		RefundHeight: entry.RefundHeight,
		AdmittedAt:   time.Now().Unix(),
	}
	body, err := json.Marshal(&item)
	if err != nil {
		return fmt.Errorf("dex-swap lookup: marshal item: %w", err)
	}
	if err := s.db.Put(itemKey(dexSwapItemPrefix, focusTxid, payload.OutputIndex), body, nil); err != nil {
		return fmt.Errorf("dex-swap lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the offer from the local index.
func (s *DEXSwapLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.DEXSwapTopicName || payload.Outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(dexSwapItemPrefix, &payload.Outpoint.Txid, payload.Outpoint.Index))
	return err
}

// OutputNoLongerRetainedInHistory is treated identically to OutputSpent —
// DEX-swap doesn't retain history.
func (s *DEXSwapLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.DEXSwapTopicName || outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(dexSwapItemPrefix, &outpoint.Txid, outpoint.Index))
	return err
}

// OutputEvicted removes the outpoint regardless of topic — DEX-swap
// stores only DEX-swap entries so the per-outpoint delete is safe.
func (s *DEXSwapLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(dexSwapItemPrefix, &outpoint.Txid, outpoint.Index))
	return err
}

// OutputBlockHeightUpdated is a no-op — DEX-swap queries don't sort by
// block height.
func (s *DEXSwapLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- query path ------------------------------------------------------------

// Lookup answers a DEX-swap query. Scans every item under the local
// prefix, applies the requested filters in-memory, and returns the
// matching outpoints as Formulas — the engine hydrates BEEF via Storage.
//
// Scan-and-filter is O(N) per query but acceptable here: DEX-swap offers
// are a low-cardinality set (typically hundreds, not millions) and
// admit/spend churn is also low. If scale changes that calculus, secondary
// indexes (by maker, by offering-token, by requesting-token) become the
// next move.
func (s *DEXSwapLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("dex-swap lookup: nil question")
	}
	if question.Service != topics.DEXSwapLookupServiceName {
		return nil, fmt.Errorf("dex-swap lookup: service %q not supported", question.Service)
	}

	var q topics.DEXSwapLookupQuery
	if err := jsonUnmarshalQuery(question.Query, &q); err != nil {
		return nil, fmt.Errorf("dex-swap lookup: %w", err)
	}

	var matches []*transaction.Outpoint
	err := scanPrefix(s.db, []byte(dexSwapItemPrefix), func(key, value []byte) error {
		var item dexSwapItem
		if err := json.Unmarshal(value, &item); err != nil {
			// Corrupt entry — skip but don't stop the scan.
			return nil
		}
		if !matchesDEXSwapItem(item, q) {
			return nil
		}
		op, ok := decodeItemKeyOutpoint(key, dexSwapItemPrefix)
		if !ok {
			return nil
		}
		matches = append(matches, op)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("dex-swap lookup: scan: %w", err)
	}
	return formulaList(matches), nil
}

// GetDocumentation returns the human-readable description.
func (s *DEXSwapLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the typed canonical metadata block.
func (s *DEXSwapLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// --- helpers ---------------------------------------------------------------

// findDEXSwapEntryForOffer scans every output of tx for a parseable
// DEX-swap metadata OP_RETURN whose OfferVout equals offerVout. Returns
// the parsed entry, or nil if no such output exists. Mirrors the
// admission-side correlation in topics.DEXSwapTopicManager.Admit.
func findDEXSwapEntryForOffer(tx *transaction.Transaction, offerVout int) *topics.DEXSwapEntry {
	for metadataVout, out := range tx.Outputs {
		if out == nil || out.LockingScript == nil {
			continue
		}
		entry := topics.ParseDEXSwapMetadata(out.LockingScript.Bytes())
		if entry == nil {
			continue
		}
		if entry.OfferVout != metadataVout-1 {
			continue
		}
		if entry.OfferVout != offerVout {
			continue
		}
		return entry
	}
	return nil
}

// matchesDEXSwapItem applies the per-query filters. List="all" short-
// circuits to true regardless of other filters because that's the
// existing behaviour callers rely on; otherwise every supplied filter
// must match.
func matchesDEXSwapItem(item dexSwapItem, q topics.DEXSwapLookupQuery) bool {
	if q.List == "all" {
		return true
	}
	if q.Maker != "" && !strings.EqualFold(item.Maker, q.Maker) {
		return false
	}
	if q.OfferingTokenTxid != "" && !containsTokenTxid(item.Offering, q.OfferingTokenTxid) {
		return false
	}
	if q.RequestingTokenTxid != "" && !containsTokenTxid(item.Requesting, q.RequestingTokenTxid) {
		return false
	}
	return true
}

// containsTokenTxid mirrors the private helper in topics/dex_swap_lookup.go
// — kept inline here so the topics file stays untouched.
func containsTokenTxid(raw json.RawMessage, txid string) bool {
	var side struct {
		Token *struct {
			Txid string `json:"txid"`
		} `json:"token"`
	}
	if err := json.Unmarshal(raw, &side); err != nil {
		return false
	}
	if side.Token == nil {
		return false
	}
	return strings.EqualFold(side.Token.Txid, txid)
}
