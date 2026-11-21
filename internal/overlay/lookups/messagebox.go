package lookups

// Canonical upstream primitive — MessageBox Lookup Service (ls_messagebox).
//
// Port source: bsv-blockchain/ts-stack
// packages/overlays/topics/src/message-box/MessageBoxLookupService.ts and
// MessageBoxStorage.ts. The prior pin,
// overlay-express-examples @481c42ed315279c17363e8b6d4c92401c8540fb7, is
// a migrated-away repo; cited only as history. Both pins describe the
// same MongoDB-backed design — ts-stack has not replaced this half with
// the newer message-box-client package's host.ts logic, which is a
// client-side (MessageBoxClient.ts) concern, not a lookup-service one.
//
// The canonical service indexes admitted MessageBox adverts into MongoDB
// and answers by identityKey (required) plus an optional exact-match
// host, newest-first (MessageBoxStorage.ts:78-94, findAdvertisements).
// This port keeps the identical query contract but is backed by a
// LevelDB key-prefix index under `lk_messagebox:` rather than a Mongo
// collection. "identityKey query missing" mirrors
// MessageBoxLookupService.ts:85 (`if (!query?.identityKey) { throw new
// Error('identityKey query missing') }`).
//
// Divergences from canonical (interop-priority rule: executable interop
// with the canonical client wins):
//   - Tie-break order. Canon sorts only by `createdAt: -1`
//     (MessageBoxStorage.ts:87); two adverts admitted in the same
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
//   - Lookup answers are capped at 10,000 BEEFs or 2 MiB of admitted BEEF
//     bytes. Results truncate newest-first; records written before byte
//     accounting are omitted because their hydration cost is unknown.
//
// See messagebox.go for the admission-side divergences.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/BSVanon/Anvil/internal/overlay/peerhygiene"
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
	// mbStoredBEEFPrefix is the canonical overlay store's per-transaction
	// BEEF key. Records written before BEEFBytes was added obtain their
	// accounting from this already-stored value during a bounded lookup scan.
	mbStoredBEEFPrefix = "beef3:"
	// mbIDPrefix indexes
	// lk_messagebox:id:<hex(identityKeyLower)>:<invertedTime>:<txid>:<vout> -> nil.
	// The inverted-time segment (mbInvertedTimeWidth fixed-width
	// digits of math.MaxInt64-AdmittedAt) makes a forward lexicographic
	// scan visit the newest record first, for free — see
	// maxCurrentHostsScan and currentRecords below.
	mbIDPrefix = "lk_messagebox:id:"

	// maxCurrentHostsScan bounds how many of an identity's newest live
	// adverts CurrentHosts decodes. Resolve runs on every message
	// send and forward (handlers_messaging.go, handlers_msg_policy.go),
	// so an identity that keeps accumulating cheap adverts (one satoshi
	// each, and coin retention no longer force-retains spent ones but an owner can
	// still hold arbitrarily many live, unspent ones) must not make
	// every message to it cost O(N) Gets and JSON decodes. 32 is a
	// generous ceiling for a real recipient's genuinely live host count
	// while bounding the worst case.
	maxCurrentHostsScan = 32

	// MessageBox lookup results use the same per-answer count and BEEF-byte
	// bounds as peer lookup answers. The engine hydrates formula references
	// before writing the public response, so the limit belongs here, before
	// that unbounded hydration loop.
	maxMessageBoxLookupBEEFs     = peerhygiene.MaxLookupOutputs
	maxMessageBoxLookupBEEFBytes = peerhygiene.MaxAnswerBEEFBytes

	// mbInvertedTimeWidth is the zero-padded decimal width of the
	// inverted-time index segment: math.MaxInt64 is 19 digits, so 20
	// digits with leading zeros never truncates and always sorts
	// correctly as a string.
	mbInvertedTimeWidth = 20
)

// messageboxRecord is the per-output state kept in LevelDB. AdmittedAt
// (Unix-nanos) drives the newest-first sort (the createdAt analogue).
type messageboxRecord struct {
	IdentityKey string `json:"identityKey"`
	Host        string `json:"host"`
	AdmittedAt  int64  `json:"admittedAt"`
	BEEFBytes   int64  `json:"beefBytes"`
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
			"an exact host. Returns output references, newest first, truncated at 10000 BEEFs or 2 MiB " +
			"of admitted BEEF bytes. Legacy records obtain their byte accounting from stored BEEF; the client decodes the PushDrop fields itself.",
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
		BEEFBytes:   int64(len(payload.AtomicBEEF)),
	}
	body, err := json.Marshal(&rec)
	if err != nil {
		return fmt.Errorf("messagebox lookup: marshal record: %w", err)
	}
	batch := new(leveldb.Batch)
	batch.Put(itemKey(mbItemPrefix, focusTxid, payload.OutputIndex), body)
	batch.Put(mbIndexKey(rec.IdentityKey, rec.AdmittedAt, focusTxid, payload.OutputIndex), nil)
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

// Lookup answers a MessageBox query: current adverts for identityKey
// (required), optionally narrowed to an exact host, newest first. It
// truncates at maxMessageBoxLookupBEEFs or maxMessageBoxLookupBEEFBytes;
// callers needing a record beyond the stable bound must query a narrower host.
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

	recs, err := s.currentRecords(strings.ToLower(q.IdentityKey), q.Host, maxMessageBoxLookupBEEFs, maxMessageBoxLookupBEEFBytes)
	if err != nil {
		return nil, err
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
