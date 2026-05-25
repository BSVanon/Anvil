package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// legacyOutputPrefix is the v2 LevelDB key family the pre-W-7 Anvil
// engine used for admitted outputs. Format:
// `ovl:<topic>:<txid-hex>:<vout-decimal>` mapping to a JSON-encoded
// AdmittedOutput { txid, vout, topic, outputScript, satoshis,
// metadata, spent }.
//
// The legacy Engine type and its outputKey() helper were stripped in
// W-7 (2026-05-16); we hard-code the prefix + parser here because
// nothing else in the v3 codebase needs to know the legacy shape.
const legacyOutputPrefix = "ovl:"

// legacyAdmittedOutput mirrors the JSON shape the legacy
// internal/overlay.AdmittedOutput type used. Kept as an unexported
// local type — the migration code is the only consumer.
type legacyAdmittedOutput struct {
	Txid         string          `json:"txid"`
	Vout         int             `json:"vout"`
	Topic        string          `json:"topic"`
	OutputScript []byte          `json:"outputScript,omitempty"`
	Satoshis     uint64          `json:"satoshis,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	Spent        bool            `json:"spent,omitempty"`
}

// MigrateOptions controls the W-4 phase B backfill behaviour.
//
// DryRun walks the legacy entries and reports counts without writing
// any v3 keys — useful for operators sanity-checking before committing.
//
// Logger is called once per migrated record (debug-level granular log)
// and on summary events. nil ⇒ silent.
//
// Clock is overridable for tests; nil ⇒ time.Now. The migration uses
// the call-time clock value as the Score (admittedAt) on every
// backfilled record — legacy entries have no admittedAt and "all are
// equally recent at migration time" is the least-surprising default
// for the new topi3 since-filter index.
//
// LookupBackfiller is invoked once per migrated record so each
// canonical lookup service can populate its per-service lk_* local
// index from the legacy metadata blob. Without this, migrated records
// exist in ovl3 but are query-invisible through engine.Lookup —
// lookups query their own lk_* indexes, not ovl3 directly. The
// callback receives the topic name, the outpoint, and the legacy
// metadata JSON; failure is logged but non-fatal (the storage record
// is already written and represents progress). cmd/anvil/migrate.go
// wires this to dispatch per-topic to the four canonical lookup
// services' BackfillFromLegacyMetadata methods.
//
// Codex review 09ddf00c90061eac caught the original implementation
// leaving lk_* empty, which would have made upgraded VPS nodes report
// zero results to apps for legitimately-admitted legacy UTXOs.
type MigrateOptions struct {
	DryRun           bool
	Logger           func(format string, args ...any)
	Clock            func() time.Time
	LookupBackfiller func(topic string, outpoint *transaction.Outpoint, metadata json.RawMessage) error
}

// MigrateStats summarises what the migration did. Returned by
// Migrate() so callers can surface a per-VPS report.
type MigrateStats struct {
	LegacyKeysSeen        int // every ovl: key visited
	Migrated              int // wrote a new ovl3 record
	AlreadyMigrated       int // ovl3 record already present (idempotent skip)
	UnparseableLegacy     int // ovl: value didn't decode as legacyAdmittedOutput (corrupt or wrong shape)
	UnparseableKey        int // ovl: key didn't split into <topic>:<txid>:<vout>
	LookupBackfilled      int // canonical lk_* index entries written via LookupBackfiller
	LookupBackfillErrors  int // LookupBackfiller invocations that returned an error (non-fatal; logged + counted)
}

// Migrate walks every legacy `ovl:<topic>:<txid>:<vout>` LevelDB key
// in db and writes the equivalent v3 records (ovl3 primary + txi3 +
// topi3 + mst3 indexes). Idempotent and safe to re-run on two axes:
//
//   - **Storage primary**: records already present in ovl3 are NOT
//     re-written. The first pass writes them; subsequent passes
//     report AlreadyMigrated.
//   - **Lookup-side**: LookupBackfiller is invoked EVERY pass for
//     every legacy record that has a non-empty metadata blob,
//     INCLUDING records whose ovl3 primary already exists. This is
//     the repair path: a node that ran the pre-fix RC migrator
//     (which left lk_* empty) can rerun anvil overlay-migrate after
//     the upgrade and have its lookup indexes repopulated even
//     though Migrated will be 0. Same for records where the first
//     pass's LookupBackfiller returned an error — the rerun retries
//     them. The 4 canonical lookup services'
//     BackfillFromLegacyMetadata methods are self-idempotent at the
//     LevelDB level (deterministic key + Put-overwrite) so calling
//     them repeatedly is safe.
//
// Sidecar families (cons3, beef, anci, appl, peer) are NOT populated
// during migration — they have no v2 source data. They start empty and
// fill as new submits + lookups arrive against the v3 engine.
//
// MerkleState for every backfilled record is set to Unmined regardless
// of the legacy entry's spent flag. The block-height + merkle-root
// fields are zero/nil. Operators wanting an Immutable state for old
// records must re-process them through the canonical engine's merkle-
// proof ingest path (out of scope here).
//
// The migration runs in a single LevelDB iteration without batching
// across records. Each record gets its own atomic leveldb.Batch so a
// process crash mid-migration leaves the database in a consistent
// state — every visited legacy key either has a complete v3 record set
// or no v3 records at all.
func Migrate(ctx context.Context, db *leveldb.DB, opts MigrateOptions) (MigrateStats, error) {
	if db == nil {
		return MigrateStats{}, errors.New("storage: migrate: nil db")
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	logf := opts.Logger
	if logf == nil {
		logf = func(string, ...any) {}
	}

	var stats MigrateStats
	migrationScore := float64(clock().Unix())

	iter := db.NewIterator(util.BytesPrefix([]byte(legacyOutputPrefix)), nil)
	defer iter.Release()

	for iter.Next() {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		stats.LegacyKeysSeen++

		topic, txid, vout, ok := parseLegacyOutputKey(iter.Key())
		if !ok {
			stats.UnparseableKey++
			logf("migrate: skipping unparseable legacy key %q", string(iter.Key()))
			continue
		}

		var legacy legacyAdmittedOutput
		if err := json.Unmarshal(iter.Value(), &legacy); err != nil {
			stats.UnparseableLegacy++
			logf("migrate: skipping unparseable legacy value at %q: %v", string(iter.Key()), err)
			continue
		}

		op := &transaction.Outpoint{Txid: *txid, Index: vout}

		// Idempotency check on the storage primary record. If ovl3
		// already exists, we don't re-write storage state — but we
		// still want to run LookupBackfiller below so reruns can
		// REPAIR missing lk_* indexes (e.g. on a node that ran the
		// pre-fix RC migrator, or on records where LookupBackfiller
		// failed transiently). Codex review 9730ed97b8e75d6c caught
		// the original short-circuit that made repair-reruns broken.
		storageAlreadyMigrated, err := db.Has(outputKey(topic, op), nil)
		if err != nil {
			return stats, fmt.Errorf("storage: migrate: check existing for %s.%d: %w", txid.String(), vout, err)
		}

		if opts.DryRun {
			if storageAlreadyMigrated {
				stats.AlreadyMigrated++
			} else {
				stats.Migrated++ // count what we WOULD have migrated
			}
			// Skip backfill in dry-run — sizing pass only.
			continue
		}

		if !storageAlreadyMigrated {
			rec := &record{
				TxidHex:      txid.String(),
				Index:        vout,
				Topic:        topic,
				Spent:        legacy.Spent,
				OutputScript: legacy.OutputScript,
				Satoshis:     legacy.Satoshis,
				Metadata:     legacy.Metadata,
				Score:        migrationScore,
				MerkleState:  uint8(engine.MerkleStateUnmined),
			}
			body, err := encodeRecord(rec)
			if err != nil {
				return stats, fmt.Errorf("storage: migrate: encode record %s.%d: %w", txid.String(), vout, err)
			}

			batch := new(leveldb.Batch)
			batch.Put(outputKey(topic, op), body)
			batch.Put(txidIndexKey(txid, topic, vout), nil)
			// topi3 only carries unspent records — spent outputs are
			// excluded from FindUTXOsForTopic by design (see
			// storage.go MarkUTXOsAsSpent's batch.Delete on topi3).
			if !legacy.Spent {
				batch.Put(topicIndexKey(topic, migrationScore, op), nil)
			}
			batch.Put(merkleIndexKey(topic, uint8(engine.MerkleStateUnmined), op), nil)

			if err := db.Write(batch, nil); err != nil {
				return stats, fmt.Errorf("storage: migrate: write batch for %s.%d: %w", txid.String(), vout, err)
			}
			stats.Migrated++
		} else {
			stats.AlreadyMigrated++
		}

		// Always attempt lookup-side backfill when a callback is
		// wired and metadata is present, INCLUDING for records whose
		// storage primary already existed. The 4 canonical lookup
		// services' BackfillFromLegacyMetadata methods are self-
		// idempotent at the LevelDB level (Put-overwrites with
		// deterministic keys) so calling them repeatedly is safe.
		//
		// This is the "repair rerun" path: a node that ran the
		// pre-fix RC migrator can rerun anvil overlay-migrate after
		// the upgrade and have its lk_* indexes repopulated even
		// though every storage record is now AlreadyMigrated. Same
		// for records where LookupBackfiller returned an error on
		// the first pass — the second pass retries them.
		if opts.LookupBackfiller != nil && len(legacy.Metadata) > 0 {
			if err := opts.LookupBackfiller(topic, op, legacy.Metadata); err != nil {
				stats.LookupBackfillErrors++
				logf("migrate: lookup backfill failed for %s.%d (topic=%s): %v", txid.String(), vout, topic, err)
				continue
			}
			stats.LookupBackfilled++
		}
	}
	if err := iter.Error(); err != nil {
		return stats, fmt.Errorf("storage: migrate: iterate ovl: prefix: %w", err)
	}
	return stats, nil
}

// parseLegacyOutputKey decodes `ovl:<topic>:<txid-hex>:<vout-decimal>`.
// Returns false for any key that doesn't fit the expected shape — the
// migration's UnparseableKey counter surfaces those as a data-
// integrity signal rather than a hard error.
func parseLegacyOutputKey(key []byte) (topic string, txid *chainhash.Hash, vout uint32, ok bool) {
	s := string(key)
	if !strings.HasPrefix(s, legacyOutputPrefix) {
		return "", nil, 0, false
	}
	rest := s[len(legacyOutputPrefix):]
	// vout is the suffix after the last ':'; txid is the 64 hex chars
	// before that; topic is everything else (may itself contain
	// underscores but not ':').
	voutIdx := strings.LastIndexByte(rest, ':')
	if voutIdx <= 64 {
		return "", nil, 0, false
	}
	voutStr := rest[voutIdx+1:]
	txidHex := rest[voutIdx-64 : voutIdx]
	if rest[voutIdx-65] != ':' {
		return "", nil, 0, false
	}
	topic = rest[:voutIdx-65]
	v, err := strconv.ParseUint(voutStr, 10, 32)
	if err != nil {
		return "", nil, 0, false
	}
	h, err := chainhash.NewHashFromHex(txidHex)
	if err != nil {
		return "", nil, 0, false
	}
	return topic, h, uint32(v), true
}
