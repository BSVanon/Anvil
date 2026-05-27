package lookups

// Canonical upstream primitive — KVStore Lookup Service (ls_kvstore).
//
// Pragmatic transitional placement: hosted in Anvil today; will be
// re-exported from `bsv-blockchain/go-overlay-discovery-services` once
// that repo gains a topic-impl partition for non-SHIP/SLAP canonical
// primitives. Port source: `ts-stack`
// `packages/overlays/topics/src/kvstore/KVStoreLookupService.ts` +
// `KVStoreStorageManager.ts` (MCP-verified, head `29aff6e`).
//
// The canonical service indexes admitted KVStore tokens into MongoDB and
// answers the BRC-35 §3.5 query schema. Anvil's port keeps the identical
// query contract (key / controller / protocolID / tags / tagQueryMode /
// limit / skip / sortOrder) but is backed by LevelDB key-prefix indexes
// under `lk_kvstore:` rather than Mongo collections.
//
// Divergences from canonical, flagged per the interop-priority rule:
//   - protocolID match: canonical stores the raw on-chain UTF-8 string
//     and compares it to JSON.stringify(query.protocolID). This port
//     does the same — it canonicalises the query protocolID to its
//     compact JSON form and string-matches the stored raw field. A token
//     whose on-chain protocolID field is non-compact would (correctly,
//     matching canonical) fail to match a compact query.
//   - sort key: canonical sorts by a server-assigned createdAt Date;
//     this port sorts by admission time (Unix-nanos at index write),
//     which is the LevelDB-local equivalent.
//   - limit is clamped to kvMaxLimit for scale safety; canonical imposes
//     no hard ceiling (default 50).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	kvItemPrefix  = "lk_kvstore:item:"  // lk_kvstore:item:<txid>:<vout> → JSON kvstoreRecord
	kvKeyPrefix   = "lk_kvstore:key:"   // lk_kvstore:key:<hex(key)>:<txid>:<vout> → nil
	kvCtrlPrefix  = "lk_kvstore:ctrl:"  // lk_kvstore:ctrl:<controllerHex>:<txid>:<vout> → nil
	kvProtoPrefix = "lk_kvstore:proto:" // lk_kvstore:proto:<hex(protocolID)>:<txid>:<vout> → nil
	kvTagPrefix   = "lk_kvstore:tag:"   // lk_kvstore:tag:<hex(tag)>:<txid>:<vout> → nil (one per tag)

	kvDefaultLimit = 50
	kvMaxLimit     = 1000
)

// kvstoreRecord is the per-output state kept in LevelDB. AdmittedAt
// (Unix-nanos) drives the asc/desc sort (the createdAt analogue).
type kvstoreRecord struct {
	Key        string   `json:"key"`
	ProtocolID string   `json:"protocol_id"`
	Controller string   `json:"controller"`
	Tags       []string `json:"tags,omitempty"`
	AdmittedAt int64    `json:"admitted_at"`
}

// KVStoreLookupService implements engine.LookupService for tm_kvstore.
type KVStoreLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewKVStoreLookupService constructs a KVStore lookup against the
// supplied LevelDB handle.
func NewKVStoreLookupService(db *leveldb.DB) *KVStoreLookupService {
	return &KVStoreLookupService{
		db: db,
		docs: "KVStore Lookup Service (BRC-35): find canonical key-value records published on-chain. " +
			"Select by key, controller (identity pubkey hex), protocolID ([level, name] array), or tags " +
			"(with tagQueryMode all/any); narrow with multiple selectors; page with limit/skip and order " +
			"with sortOrder (desc default). Returns output references; the wallet fetches + decrypts values.",
		meta: &overlay.MetaData{
			Name:        topics.KVStoreLookupServiceName,
			Description: "BRC-35 canonical key-value record resolution",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion that the type satisfies engine.LookupService.
var _ engine.LookupService = (*KVStoreLookupService)(nil)

// --- event handlers --------------------------------------------------------

// OutputAdmittedByTopic indexes a freshly-admitted KVStore token.
func (s *KVStoreLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.KVStoreTopicName {
		return nil
	}
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("kvstore lookup: %w", err)
	}
	if int(payload.OutputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("kvstore lookup: output index %d out of range for tx %s", payload.OutputIndex, focusTxid.String())
	}
	out := tx.Outputs[payload.OutputIndex]
	if out.LockingScript == nil {
		return nil
	}
	entry, err := topics.ParseKVStoreOutput(out.LockingScript.Bytes())
	if err != nil || entry == nil {
		// Admission already verified shape + signature; a re-parse miss
		// here is non-fatal.
		return nil
	}
	rec := kvstoreRecord{
		Key:        entry.Key,
		ProtocolID: entry.ProtocolID,
		Controller: strings.ToLower(entry.Controller),
		Tags:       entry.Tags,
		AdmittedAt: nowUnixNano(),
	}
	body, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("kvstore lookup: marshal record: %w", err)
	}
	batch := new(leveldb.Batch)
	batch.Put(itemKey(kvItemPrefix, focusTxid, payload.OutputIndex), body)
	if rec.Key != "" {
		batch.Put(kvIndexKey(kvKeyPrefix, rec.Key, focusTxid, payload.OutputIndex), nil)
	}
	if rec.Controller != "" {
		batch.Put(kvIndexKey(kvCtrlPrefix, rec.Controller, focusTxid, payload.OutputIndex), nil)
	}
	if rec.ProtocolID != "" {
		batch.Put(kvIndexKey(kvProtoPrefix, rec.ProtocolID, focusTxid, payload.OutputIndex), nil)
	}
	for _, tag := range rec.Tags {
		batch.Put(kvIndexKey(kvTagPrefix, tag, focusTxid, payload.OutputIndex), nil)
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("kvstore lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the record when a KVStore token is spent (key
// update or deletion).
func (s *KVStoreLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.KVStoreTopicName || payload.Outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&payload.Outpoint.Txid, payload.Outpoint.Index)
}

// OutputNoLongerRetainedInHistory is treated like OutputSpent.
func (s *KVStoreLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.KVStoreTopicName || outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputEvicted removes the record regardless of topic.
func (s *KVStoreLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputBlockHeightUpdated is a no-op.
func (s *KVStoreLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- query path ------------------------------------------------------------

// Lookup answers a KVStore query. At least one selector is required; the
// supplied selectors AND-narrow the candidate set, which is then ordered
// by admission time and paginated.
func (s *KVStoreLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("kvstore lookup: nil question")
	}
	if question.Service != topics.KVStoreLookupServiceName {
		return nil, fmt.Errorf("kvstore lookup: service %q not supported", question.Service)
	}
	var q topics.KVStoreLookupQuery
	if err := jsonUnmarshalQuery(question.Query, &q); err != nil {
		return nil, fmt.Errorf("kvstore lookup: %w", err)
	}

	key := q.Key
	controller := strings.ToLower(q.Controller)
	protoCanonical, hasProto := canonicalProtocolID(q.ProtocolID)
	tags := q.Tags

	// Mirror the canonical validateQuerySelectors: at least one of key,
	// controller, protocolID (a 2-element array), or tags.
	if key == "" && controller == "" && !hasProto && len(tags) == 0 {
		return nil, errors.New("kvstore lookup: must specify at least one selector: key, controller, protocolID, or tags")
	}

	tagMode := strings.ToLower(q.TagQueryMode)
	if tagMode != "any" {
		tagMode = "all"
	}

	// Pick the most selective available index for the candidate scan,
	// then filter by the remaining predicates in memory.
	candidates, err := s.candidateOutpoints(key, controller, protoCanonical, hasProto, tags)
	if err != nil {
		return nil, err
	}

	type hit struct {
		op *transaction.Outpoint
		at int64
	}
	var hits []hit
	seen := make(map[string]struct{}, len(candidates))
	for _, op := range candidates {
		dedupe := op.Txid.String() + ":" + strconv.FormatUint(uint64(op.Index), 10)
		if _, ok := seen[dedupe]; ok {
			continue
		}
		seen[dedupe] = struct{}{}

		body, err := s.db.Get(itemKey(kvItemPrefix, &op.Txid, op.Index), nil)
		if err != nil {
			continue // index drift — skip
		}
		var rec kvstoreRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			continue
		}
		if key != "" && rec.Key != key {
			continue
		}
		if controller != "" && rec.Controller != controller {
			continue
		}
		if hasProto && rec.ProtocolID != protoCanonical {
			continue
		}
		if len(tags) > 0 && !tagsMatch(rec.Tags, tags, tagMode) {
			continue
		}
		hits = append(hits, hit{op: op, at: rec.AdmittedAt})
	}

	// Sort by admission time. desc (most-recent first) is the default;
	// asc when explicitly requested.
	asc := strings.ToLower(q.SortOrder) == "asc"
	sort.SliceStable(hits, func(i, j int) bool {
		if asc {
			return hits[i].at < hits[j].at
		}
		return hits[i].at > hits[j].at
	})

	paged := applyPagination(hits, q.Limit, q.Skip, kvDefaultLimit, kvMaxLimit)
	ops := make([]*transaction.Outpoint, 0, len(paged))
	for _, h := range paged {
		ops = append(ops, h.op)
	}
	return formulaList(ops), nil
}

// GetDocumentation returns the human-readable description.
func (s *KVStoreLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the canonical metadata block.
func (s *KVStoreLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// --- internal helpers ------------------------------------------------------

// candidateOutpoints returns the candidate outpoint set from the most
// selective available index, in selector-priority order
// (key > controller > protocolID > tags). The caller AND-filters the
// result against the remaining predicates.
func (s *KVStoreLookupService) candidateOutpoints(key, controller, protoCanonical string, hasProto bool, tags []string) ([]*transaction.Outpoint, error) {
	switch {
	case key != "":
		return s.scanIndex(kvKeyPrefix, key)
	case controller != "":
		return s.scanIndex(kvCtrlPrefix, controller)
	case hasProto:
		return s.scanIndex(kvProtoPrefix, protoCanonical)
	default:
		// tags-only: union the per-tag buckets.
		var all []*transaction.Outpoint
		for _, tag := range tags {
			ops, err := s.scanIndex(kvTagPrefix, tag)
			if err != nil {
				return nil, err
			}
			all = append(all, ops...)
		}
		return all, nil
	}
}

// scanIndex collects every outpoint under <prefix><hex(value)>:.
func (s *KVStoreLookupService) scanIndex(prefix, value string) ([]*transaction.Outpoint, error) {
	fullPrefix := []byte(prefix + hex.EncodeToString([]byte(value)) + ":")
	var ops []*transaction.Outpoint
	err := scanPrefix(s.db, fullPrefix, func(k, _ []byte) error {
		if op, ok := decodeKVIndexOutpoint(k, len(fullPrefix)); ok {
			ops = append(ops, op)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvstore lookup: scan %s: %w", prefix, err)
	}
	return ops, nil
}

// removeOutpoint deletes the record + every secondary index entry.
func (s *KVStoreLookupService) removeOutpoint(txid *chainhash.Hash, vout uint32) error {
	primary := itemKey(kvItemPrefix, txid, vout)
	body, err := s.db.Get(primary, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("kvstore lookup: read for remove: %w", err)
	}
	var rec kvstoreRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return s.db.Delete(primary, nil)
	}
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	if rec.Key != "" {
		batch.Delete(kvIndexKey(kvKeyPrefix, rec.Key, txid, vout))
	}
	if rec.Controller != "" {
		batch.Delete(kvIndexKey(kvCtrlPrefix, rec.Controller, txid, vout))
	}
	if rec.ProtocolID != "" {
		batch.Delete(kvIndexKey(kvProtoPrefix, rec.ProtocolID, txid, vout))
	}
	for _, tag := range rec.Tags {
		batch.Delete(kvIndexKey(kvTagPrefix, tag, txid, vout))
	}
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("kvstore lookup: delete batch: %w", err)
	}
	return nil
}

// kvIndexKey produces <prefix><hex(value)>:<txid>:<vout>. The value is
// hex-encoded so arbitrary UTF-8 keys/tags/protocolIDs can't break the
// ':'-delimited outpoint suffix.
func kvIndexKey(prefix, value string, txid *chainhash.Hash, vout uint32) []byte {
	return []byte(prefix + hex.EncodeToString([]byte(value)) + ":" + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

// decodeKVIndexOutpoint extracts the trailing <txid>:<vout> from an index
// key, given the length of the <prefix><hex(value)>: portion.
func decodeKVIndexOutpoint(key []byte, fullPrefixLen int) (*transaction.Outpoint, bool) {
	if len(key) < fullPrefixLen {
		return nil, false
	}
	rest := string(key[fullPrefixLen:])
	idx := strings.LastIndexByte(rest, ':')
	if idx != 64 {
		return nil, false
	}
	h, err := chainhash.NewHashFromHex(rest[:64])
	if err != nil {
		return nil, false
	}
	v, err := strconv.ParseUint(rest[idx+1:], 10, 32)
	if err != nil {
		return nil, false
	}
	return &transaction.Outpoint{Txid: *h, Index: uint32(v)}, true
}

// canonicalProtocolID converts a query protocolID ([level, name] array)
// to its compact JSON form for comparison against the stored field,
// matching the canonical JSON.stringify(query.protocolID). Returns
// ("", false) when the protocolID is absent or not a 2-element array.
func canonicalProtocolID(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var arr []interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return "", false
	}
	if len(arr) != 2 {
		return "", false
	}
	b, err := json.Marshal(arr)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// tagsMatch reports whether recordTags satisfy queryTags under the given
// mode: "all" requires every query tag present; "any" requires at least
// one.
func tagsMatch(recordTags, queryTags []string, mode string) bool {
	if len(queryTags) == 0 {
		return true
	}
	have := make(map[string]struct{}, len(recordTags))
	for _, t := range recordTags {
		have[t] = struct{}{}
	}
	if mode == "any" {
		for _, t := range queryTags {
			if _, ok := have[t]; ok {
				return true
			}
		}
		return false
	}
	// "all"
	for _, t := range queryTags {
		if _, ok := have[t]; !ok {
			return false
		}
	}
	return true
}
