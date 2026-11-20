package lookups

// Canonical upstream primitive — MessageBox Lookup Service (ls_messagebox).
//
// Port source: overlay-express-examples
// `src/services/message-box/MessageBoxLookupService.ts` +
// `MessageBoxStorage.ts`, pinned commit
// 481c42ed315279c17363e8b6d4c92401c8540fb7 (MCP-verified via brc100-mcp
// read_file).
//
// The canonical service indexes admitted MessageBox adverts into MongoDB
// and answers by identityKey (required) plus an optional exact-match
// host, newest-first (MessageBoxStorage.ts:58-78). This port keeps the
// identical query contract but is backed by a LevelDB key-prefix index
// under `lk_messagebox:` rather than a Mongo collection.
//
// Divergences from canonical (interop-priority rule: executable interop
// with the canonical client wins):
//   - Tie-break order. Canon sorts only by `createdAt: -1`
//     (MessageBoxStorage.ts:68); two adverts admitted in the same
//     millisecond fall to MongoDB's unspecified natural order. This port
//     sorts by AdmittedAt (Unix-nanos, nowUnixNano — common.go) descending
//     and breaks a tie by outpoint (txid, then vout) ascending, for a
//     deterministic, reproducible order. No client relies on tie order
//     within the same instant, so this is a safe, cited divergence, not
//     an interop break.
//   - identityKey casing. Canon's Mongo filter is a case-sensitive exact
//     string match; in practice @bsv/sdk's Utils.toHex always produces
//     lowercase hex, so canon is never actually exercised with mixed
//     case. This port lowercases both the stored and queried identityKey
//     explicitly, matching Anvil's existing controller/identity-field
//     convention elsewhere (e.g. kvstore.go's Controller).
//   - No limit/skip/pagination. Canon's findAdvertisements takes none
//     either (MessageBoxStorage.ts:58-78) — a live advert set per
//     identity is small (bounded by how many adverts that identity
//     hasn't spent yet), so this port returns every match, unbounded,
//     exactly like canon.
//
// See messagebox.go for the admission-side divergences.

import (
	"context"
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
	mbItemPrefix = "lk_messagebox:item:" // lk_messagebox:item:<txid>:<vout> -> JSON messageboxRecord
	mbIDPrefix   = "lk_messagebox:id:"   // lk_messagebox:id:<hex(identityKeyLower)>:<txid>:<vout> -> nil
)

// messageboxRecord is the per-output state kept in LevelDB. AdmittedAt
// (Unix-nanos) drives the newest-first sort (the createdAt analogue).
type messageboxRecord struct {
	IdentityKey string `json:"identityKey"`
	Host        string `json:"host"`
	AdmittedAt  int64  `json:"admittedAt"`
}

// MessageBoxLookupService implements engine.LookupService for
// tm_messagebox.
type MessageBoxLookupService struct {
	db   *leveldb.DB
	docs string
	meta *overlay.MetaData
}

// NewMessageBoxLookupService constructs a MessageBox lookup against the
// supplied LevelDB handle.
func NewMessageBoxLookupService(db *leveldb.DB) *MessageBoxLookupService {
	return &MessageBoxLookupService{
		db: db,
		docs: "MessageBox Lookup Service (BRC-33): resolve which host(s) a recipient identity has " +
			"advertised for message routing. Query by identityKey (required), optionally narrowed to " +
			"an exact host. Returns output references, newest first; the client decodes the PushDrop " +
			"fields itself.",
		meta: &overlay.MetaData{
			Name:        topics.MessageBoxLookupServiceName,
			Description: "BRC-33 MessageBox host-advertisement resolution",
			Version:     "1.0.0",
		},
	}
}

// Compile-time assertion that the type satisfies engine.LookupService.
var _ engine.LookupService = (*MessageBoxLookupService)(nil)

// --- event handlers --------------------------------------------------------

// OutputAdmittedByTopic indexes a freshly-admitted MessageBox advert.
func (s *MessageBoxLookupService) OutputAdmittedByTopic(ctx context.Context, payload *engine.OutputAdmittedByTopic) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.MessageBoxTopicName {
		return nil
	}
	tx, focusTxid, err := loadFocusTx(payload.AtomicBEEF)
	if err != nil {
		return fmt.Errorf("messagebox lookup: %w", err)
	}
	if int(payload.OutputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("messagebox lookup: output index %d out of range for tx %s", payload.OutputIndex, focusTxid.String())
	}
	out := tx.Outputs[payload.OutputIndex]
	if out.LockingScript == nil {
		return nil
	}
	entry, err := topics.ParseMessageBoxOutput(out.LockingScript.Bytes())
	if err != nil || entry == nil {
		// Admission already verified shape + signature; a re-parse miss
		// here is non-fatal.
		return nil
	}
	rec := messageboxRecord{
		IdentityKey: strings.ToLower(entry.IdentityKey),
		Host:        entry.Host,
		AdmittedAt:  nowUnixNano(),
	}
	body, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("messagebox lookup: marshal record: %w", err)
	}
	batch := new(leveldb.Batch)
	batch.Put(itemKey(mbItemPrefix, focusTxid, payload.OutputIndex), body)
	batch.Put(mbIndexKey(rec.IdentityKey, focusTxid, payload.OutputIndex), nil)
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("messagebox lookup: write index: %w", err)
	}
	return nil
}

// OutputSpent removes the record when an advert is spent (revoked or
// superseded by a new advert).
func (s *MessageBoxLookupService) OutputSpent(ctx context.Context, payload *engine.OutputSpent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if payload == nil || payload.Topic != topics.MessageBoxTopicName || payload.Outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&payload.Outpoint.Txid, payload.Outpoint.Index)
}

// OutputNoLongerRetainedInHistory is treated like OutputSpent.
func (s *MessageBoxLookupService) OutputNoLongerRetainedInHistory(ctx context.Context, outpoint *transaction.Outpoint, topic string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if topic != topics.MessageBoxTopicName || outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputEvicted removes the record regardless of topic.
func (s *MessageBoxLookupService) OutputEvicted(ctx context.Context, outpoint *transaction.Outpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if outpoint == nil {
		return nil
	}
	return s.removeOutpoint(&outpoint.Txid, outpoint.Index)
}

// OutputBlockHeightUpdated is a no-op.
func (s *MessageBoxLookupService) OutputBlockHeightUpdated(ctx context.Context, txid *chainhash.Hash, blockHeight uint32, blockIndex uint64) error {
	return nil
}

// --- query path ------------------------------------------------------------

// Lookup answers a MessageBox query: every current advert for
// identityKey (required), optionally narrowed to an exact host, newest
// first.
func (s *MessageBoxLookupService) Lookup(ctx context.Context, question *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if question == nil {
		return nil, errors.New("messagebox lookup: nil question")
	}
	if question.Service != topics.MessageBoxLookupServiceName {
		return nil, fmt.Errorf("messagebox lookup: service %q not supported", question.Service)
	}
	var q topics.MessageBoxLookupQuery
	if err := jsonUnmarshalQuery(question.Query, &q); err != nil {
		return nil, fmt.Errorf("messagebox lookup: %w", err)
	}
	if strings.TrimSpace(q.IdentityKey) == "" {
		return nil, errors.New("messagebox lookup: identityKey query missing")
	}

	recs, err := s.currentRecords(strings.ToLower(q.IdentityKey))
	if err != nil {
		return nil, err
	}
	if q.Host != "" {
		filtered := recs[:0]
		for _, r := range recs {
			if r.host == q.Host {
				filtered = append(filtered, r)
			}
		}
		recs = filtered
	}

	ops := make([]*transaction.Outpoint, 0, len(recs))
	for _, r := range recs {
		ops = append(ops, r.op)
	}
	return formulaList(ops), nil
}

// GetDocumentation returns the human-readable description.
func (s *MessageBoxLookupService) GetDocumentation() string { return s.docs }

// GetMetaData returns the canonical metadata block.
func (s *MessageBoxLookupService) GetMetaData() *overlay.MetaData { return s.meta }

// --- internal helpers --------------------------------------------------

type mbHit struct {
	op   *transaction.Outpoint
	host string
	at   int64
}

// currentRecords returns every live (unspent, unevicted) advert for
// identityKeyLower, newest first (ties broken by outpoint ascending —
// see the tie-break divergence above).
func (s *MessageBoxLookupService) currentRecords(identityKeyLower string) ([]mbHit, error) {
	fullPrefix := []byte(mbIDPrefix + identityKeyLower + ":")
	var hits []mbHit
	err := scanPrefix(s.db, fullPrefix, func(k, _ []byte) error {
		op, ok := decodeMBIndexOutpoint(k, len(fullPrefix))
		if !ok {
			return nil
		}
		body, err := s.db.Get(itemKey(mbItemPrefix, &op.Txid, op.Index), nil)
		if err != nil {
			return nil // index drift — skip
		}
		var rec messageboxRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil
		}
		hits = append(hits, mbHit{op: op, host: rec.Host, at: rec.AdmittedAt})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("messagebox lookup: scan %s: %w", mbIDPrefix, err)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].at != hits[j].at {
			return hits[i].at > hits[j].at // newest first
		}
		if hits[i].op.Txid != hits[j].op.Txid {
			return hits[i].op.Txid.String() < hits[j].op.Txid.String()
		}
		return hits[i].op.Index < hits[j].op.Index
	})
	return hits, nil
}

// CurrentHosts returns the raw (un-normalised) host string of every live
// advert for identityKeyHex, in no particular order — decision 2's
// "ordering doesn't matter" rule. This is a native Go side-channel for
// messaging.HomeResolver: it reads the same `lk_messagebox:` index this
// service's own Lookup answers from (the LevelDB handle is the single
// source of truth), skipping the BEEF/output-list round trip the
// external ls_messagebox HTTP contract requires — the Home Rule check
// runs on every message send/forward and would otherwise re-fetch and
// re-decode a transaction per call. Returns (nil, nil) for an unknown or
// unadvertised identity.
func (s *MessageBoxLookupService) CurrentHosts(identityKeyHex string) ([]string, error) {
	hits, err := s.currentRecords(strings.ToLower(strings.TrimSpace(identityKeyHex)))
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(hits))
	for _, h := range hits {
		hosts = append(hosts, h.host)
	}
	return hosts, nil
}

// removeOutpoint deletes the record + its identityKey index entry.
func (s *MessageBoxLookupService) removeOutpoint(txid *chainhash.Hash, vout uint32) error {
	primary := itemKey(mbItemPrefix, txid, vout)
	body, err := s.db.Get(primary, nil)
	if err != nil {
		if errors.Is(err, leveldb.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("messagebox lookup: read for remove: %w", err)
	}
	var rec messageboxRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return s.db.Delete(primary, nil)
	}
	batch := new(leveldb.Batch)
	batch.Delete(primary)
	batch.Delete(mbIndexKey(rec.IdentityKey, txid, vout))
	if err := s.db.Write(batch, nil); err != nil {
		return fmt.Errorf("messagebox lookup: delete batch: %w", err)
	}
	return nil
}

// mbIndexKey produces <mbIDPrefix><identityKeyLower>:<txid>:<vout>. The
// identity key is already hex (fixed alphabet, no ':'), so unlike
// kvstore's free-text keys it needs no extra hex-escaping layer.
func mbIndexKey(identityKeyLower string, txid *chainhash.Hash, vout uint32) []byte {
	return []byte(mbIDPrefix + identityKeyLower + ":" + txid.String() + ":" + strconv.FormatUint(uint64(vout), 10))
}

// decodeMBIndexOutpoint extracts the trailing <txid>:<vout> from an index
// key, given the length of the <mbIDPrefix><identityKeyLower>: portion.
func decodeMBIndexOutpoint(key []byte, fullPrefixLen int) (*transaction.Outpoint, bool) {
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
