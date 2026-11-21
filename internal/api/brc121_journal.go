package api

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	anvilstore "github.com/BSVanon/Anvil/internal/store"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// The journal keeps each BRC-121 payment the node verified but did not
// record. The payer's wallet broadcasts a payment before the node sees it
// (402-pay client.ts:74-94), so a payment that passed every check but was not
// recorded (ARC busy, slow or unreachable, its answer still on its way, or
// the wallet failing) may still be mined, paying a key the node wallet finds
// only from the payment's own remittance. The journal keeps that remittance,
// with the payment, until the sweep (brc121_sweep.go) records it or learns
// the network refused it. A payment ARC refused outright is never kept.

const (
	// maxBRC121JournalEntries bounds the journal. A payment that would go
	// past it is not kept, and is counted and logged.
	maxBRC121JournalEntries = 4096
	// brc121JournalTTL is how long an entry is kept before the sweep drops
	// it.
	brc121JournalTTL = 7 * 24 * time.Hour
)

var errBRC121JournalFull = errors.New("the unclaimed-payment journal is full")

// brc121Entry is one kept payment: what recording it needs, and when it was
// kept.
type brc121Entry struct {
	TxID     string `json:"txid"`
	Vout     uint32 `json:"vout"`
	Nonce    string `json:"nonce"`
	Time     string `json:"time"`
	Sender   string `json:"sender"`
	Satoshis uint64 `json:"satoshis"`
	BEEF     []byte `json:"beef"` // the subject's closure, as an Atomic BEEF
	Kept     int64  `json:"kept"` // unix seconds, the node's clock
}

// brc121Journal is the journal's LevelDB, with every entry's txid and keep
// time held in memory so its size and age are read without loading a BEEF.
// Writes are synced.
type brc121Journal struct {
	db   *leveldb.DB
	mu   sync.Mutex
	kept map[string]int64 // txid -> Kept
}

var (
	brc121EntryPrefix = []byte("e/")
	brc121KeptPrefix  = []byte("k/")
	brc121Sync        = &opt.WriteOptions{Sync: true}
)

func openBRC121Journal(dir string) (*brc121Journal, error) {
	db, err := anvilstore.OpenWithRecover(dir, nil)
	if err != nil {
		return nil, fmt.Errorf("open the BRC-121 journal: %w", err)
	}
	j := &brc121Journal{db: db, kept: make(map[string]int64)}
	it := db.NewIterator(util.BytesPrefix(brc121KeptPrefix), nil)
	for it.Next() {
		if v := it.Value(); len(v) == 8 {
			j.kept[string(it.Key()[len(brc121KeptPrefix):])] = int64(binary.BigEndian.Uint64(v))
		}
	}
	it.Release()
	if err := it.Error(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read the BRC-121 journal: %w", err)
	}
	return j, nil
}

func (j *brc121Journal) close() error { return j.db.Close() }

// add keeps e. A txid already kept is kept once, at its first time.
func (j *brc121Journal) add(e *brc121Entry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.kept[e.TxID]; ok {
		return nil
	}
	if len(j.kept) >= maxBRC121JournalEntries {
		return errBRC121JournalFull
	}
	v, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(e.Kept))
	batch := new(leveldb.Batch)
	batch.Put(append(append([]byte{}, brc121EntryPrefix...), e.TxID...), v)
	batch.Put(append(append([]byte{}, brc121KeptPrefix...), e.TxID...), at[:])
	if err := j.db.Write(batch, brc121Sync); err != nil {
		return err
	}
	j.kept[e.TxID] = e.Kept
	return nil
}

// get loads the entry kept for txid.
func (j *brc121Journal) get(txid string) (*brc121Entry, error) {
	v, err := j.db.Get(append(append([]byte{}, brc121EntryPrefix...), txid...), nil)
	if err != nil {
		return nil, err
	}
	var e brc121Entry
	if err := json.Unmarshal(v, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// remove drops txid's entry, if one is kept.
func (j *brc121Journal) remove(txid string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.kept[txid]; !ok {
		return
	}
	batch := new(leveldb.Batch)
	batch.Delete(append(append([]byte{}, brc121EntryPrefix...), txid...))
	batch.Delete(append(append([]byte{}, brc121KeptPrefix...), txid...))
	if err := j.db.Write(batch, brc121Sync); err == nil {
		delete(j.kept, txid)
	}
}

// has reports whether txid is kept.
func (j *brc121Journal) has(txid string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.kept[txid]
	return ok
}

// stats is the number of entries and the age of the oldest at now.
func (j *brc121Journal) stats(now time.Time) (int, time.Duration) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var oldest int64
	for _, at := range j.kept {
		if oldest == 0 || at < oldest {
			oldest = at
		}
	}
	if oldest == 0 {
		return len(j.kept), 0
	}
	return len(j.kept), now.Sub(time.Unix(oldest, 0))
}

// due is the txids kept at or before cutoff, oldest first.
func (j *brc121Journal) due(cutoff time.Time) []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	ids := make([]string, 0, len(j.kept))
	for id, at := range j.kept {
		if at <= cutoff.Unix() {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(a, b int) bool {
		if j.kept[ids[a]] != j.kept[ids[b]] {
			return j.kept[ids[a]] < j.kept[ids[b]]
		}
		return ids[a] < ids[b]
	})
	return ids
}

// keep records p in the journal. A full journal refuses it: that is counted,
// and logged at most once a minute.
func (b *brc121Gate) keep(p *brc121Payment) {
	err := b.journal.add(&brc121Entry{
		TxID: p.txid.String(), Vout: p.vout, Nonce: p.nonce, Time: p.time,
		Sender: p.sender.ToDERHex(), Satoshis: p.sats, BEEF: p.atomic, Kept: b.now().Unix(),
	})
	switch {
	case err == nil:
		b.counts.add(&b.counts.journaled)
	case errors.Is(err, errBRC121JournalFull):
		b.counts.add(&b.counts.full)
		b.logFullOnce()
	default:
		b.logger.Error("BRC-121 journal write failed", "txid", p.txid.String(), "error", err)
	}
}

// logFullOnce logs that the journal is full, at most once a minute.
func (b *brc121Gate) logFullOnce() {
	b.counts.mu.Lock()
	now := b.now()
	due := now.Sub(b.counts.fullLogged) >= time.Minute
	if due {
		b.counts.fullLogged = now
	}
	full := b.counts.full
	b.counts.mu.Unlock()
	if due {
		b.logger.Warn("BRC-121 journal is full; a verified payment was not kept", "cap", maxBRC121JournalEntries, "refused_so_far", full)
	}
}
