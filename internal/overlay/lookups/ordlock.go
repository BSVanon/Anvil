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

const ordLockItemPrefix = "lk_ordlock:item:" // lk_ordlock:item:<txid>:<vout> → entry JSON

const (
	ordLockDefaultLimit = 100
	ordLockMaxLimit     = 500
)

// OrdLockLookupService implements engine.LookupService for the OrdLock
// listings topic (1Sat OrdLock self-settling fixed-price BSV-20/21
// covenants).
type OrdLockLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewOrdLockLookupService constructs an OrdLock-listings lookup backed
// by the given LevelDB handle.
func NewOrdLockLookupService(db *leveldb.DB) *OrdLockLookupService {
	return &OrdLockLookupService{
		db:   db,
		docs: "OrdLock Listings Lookup: query active 1Sat OrdLock fixed-price listings. Filter by tokenId (BSV-21), tick (BSV-20), or cancelAddress; paginate via limit/offset; default sort is admittedAt descending.",
		meta: &overlay.MetaData{
			Name:        topics.OrdLockLookupServiceName,
			Description: "OrdLock 1Sat listing queries (BSV-20/21)",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion.
var _ engine.LookupService = (*OrdLockLookupService)(nil)

// --- event handlers --------------------------------------------------------

// BackfillFromLegacyMetadata populates this service's lk_ordlock
// index for a single legacy AdmittedOutput. Used by W-4 phase B
// migration. metadata is a JSON-encoded topics.OrdLockEntry. See the
// UHRP backfill doc-comment for the canonical /lookup BEEF-empty
// limitation that applies equally here.
func (s *OrdLockLookupService) BackfillFromLegacyMetadata(outpoint *transaction.Outpoint, metadata json.RawMessage) error {
	if outpoint == nil {
		return errors.New("ordlock backfill: nil outpoint")
	}
	if len(metadata) == 0 {
		return errors.New("ordlock backfill: empty metadata")
	}
	var entry topics.OrdLockEntry
	if err := json.Unmarshal(metadata, &entry); err != nil {
		return fmt.Errorf("ordlock backfill: decode metadata: %w", err)
	}
	// Backfill keeps the legacy AdmittedAt (RFC3339 string) if the
	// metadata carries it; the canonical lookup uses string-compare
	// sort, so legacy timestamps work without renormalisation.
	body, err := json.Marshal(&entry)
	if err != nil {
		return fmt.Errorf("ordlock backfill: marshal entry: %w", err)
	}
	if err := s.db.Put(itemKey(ordLockItemPrefix, &outpoint.Txid, outpoint.Index), body, nil); err != nil {
		return fmt.Errorf("ordlock backfill: write item: %w", err)
	}
	return nil
}

// OutputAdmittedByTopic parses the OrdLock covenant in the admitted
// output's locking script via topics.ParseOrdLockScript and stores the
// resulting entry in the local index. OrdLock has no "metadata
// elsewhere" pattern — each admitted UTXO carries its own covenant — so
// this is a single per-output extraction.
func (s *OrdLockLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.OrdLockTopicName {
		return nil
	}
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("ordlock lookup: %w", err)
	}
	if int(payload.OutputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("ordlock lookup: output index %d out of range for tx %s", payload.OutputIndex, focusTxid.String())
	}
	out := tx.Outputs[payload.OutputIndex]
	if out.LockingScript == nil {
		return nil
	}
	entry := topics.ParseOrdLockScript(out.LockingScript.Bytes())
	if entry == nil {
		return nil
	}
	// Mirror the topic-side stamping so the entry stored here is
	// indistinguishable from the one the existing engine path produces.
	entry.Outpoint = fmt.Sprintf("%s_%d", focusTxid.String(), payload.OutputIndex)
	entry.AdmittedAt = time.Now().UTC().Format(time.RFC3339)

	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("ordlock lookup: marshal entry: %w", err)
	}
	if err := s.db.Put(itemKey(ordLockItemPrefix, focusTxid, payload.OutputIndex), body, nil); err != nil {
		return fmt.Errorf("ordlock lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the listing from the local index when its UTXO is
// spent. This is the path that finally resolves OrdLock N1 (stale-
// listing reconciliation) — once the engine wires up to GASP/BRC-64 the
// callback fires regardless of how the spending tx arrived.
func (s *OrdLockLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.OrdLockTopicName || payload.Outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(ordLockItemPrefix, &payload.Outpoint.Txid, payload.Outpoint.Index))
	return err
}

// OutputNoLongerRetainedInHistory is treated identically to OutputSpent.
func (s *OrdLockLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.OrdLockTopicName || outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(ordLockItemPrefix, &outpoint.Txid, outpoint.Index))
	return err
}

// OutputEvicted removes the outpoint regardless of topic.
func (s *OrdLockLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	_, err := deleteItem(s.db, itemKey(ordLockItemPrefix, &outpoint.Txid, outpoint.Index))
	return err
}

// OutputBlockHeightUpdated is a no-op — listings are sorted by admittedAt,
// not by block height.
func (s *OrdLockLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- query path ------------------------------------------------------------

// Lookup answers an OrdLock listings query. Filters by tokenId / tick /
// cancelAddress, sorts admittedAt-descending, paginates with limit+offset,
// returns formulas (engine hydrates BEEF). Behaviour-equivalent to the
// existing topics.OrdLockLookupService, just rebuilt against the
// canonical event-driven model.
func (s *OrdLockLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("ordlock lookup: nil question")
	}
	if question.Service != topics.OrdLockLookupServiceName {
		return nil, fmt.Errorf("ordlock lookup: service %q not supported", question.Service)
	}

	var q topics.OrdLockQuery
	if err := jsonUnmarshalQuery(question.Query, &q); err != nil {
		return nil, fmt.Errorf("ordlock lookup: %w", err)
	}

	cancelPkhFilter, err := topics.NormalizeCancelFilter(q.CancelAddress)
	if err != nil {
		return nil, err
	}
	tickFilter := strings.ToUpper(strings.TrimSpace(q.Tick))

	type pair struct {
		op    *transaction.Outpoint
		entry topics.OrdLockEntry
	}
	var matches []pair
	err = scanPrefix(s.db, []byte(ordLockItemPrefix), func(key, value []byte) error {
		var entry topics.OrdLockEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return nil
		}
		if !matchesOrdLockEntry(entry, q.TokenId, tickFilter, cancelPkhFilter) {
			return nil
		}
		op, ok := decodeItemKeyOutpoint(key, ordLockItemPrefix)
		if !ok {
			return nil
		}
		matches = append(matches, pair{op: op, entry: entry})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ordlock lookup: scan: %w", err)
	}

	// AdmittedAt is RFC3339 UTC and lexicographically sortable.
	sort.SliceStable(matches, func(a, b int) bool {
		return matches[a].entry.AdmittedAt > matches[b].entry.AdmittedAt
	})

	page := applyPagination(matches, q.Limit, q.Offset, ordLockDefaultLimit, ordLockMaxLimit)
	outpoints := make([]*transaction.Outpoint, 0, len(page))
	for _, p := range page {
		outpoints = append(outpoints, p.op)
	}
	return formulaList(outpoints), nil
}

// GetDocumentation returns the human-readable description.
func (s *OrdLockLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the typed canonical metadata block.
func (s *OrdLockLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// matchesOrdLockEntry applies the filter rules. tokenId + tick are
// mutually exclusive: when tokenId is supplied we ignore tick (matches
// the existing topics.matchesOrdLockQuery behaviour).
func matchesOrdLockEntry(entry topics.OrdLockEntry, tokenId, tickUpper, cancelPkhFilterLower string) bool {
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
