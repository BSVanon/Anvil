package ordtrack

import (
	"encoding/json"
	"fmt"
	"strconv"

	anvilstore "github.com/BSVanon/Anvil/internal/store"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Link statuses and kinds, as stored.
const (
	statusMined   = "mined"
	statusPending = "pending"
	kindOrigin    = "origin"
)

// link is one outpoint in a chain, the origin first.
type link struct {
	Outpoint    string `json:"outpoint"`
	Content     string `json:"content,omitempty"` // effective inscription outpoint at this location
	ContentSeq  int    `json:"content_seq,omitempty"`
	Txid        string `json:"txid"`
	Prev        string `json:"prev,omitempty"` // the outpoint it spent; "" for the origin
	Kind        string `json:"kind"`           // origin, transfer, end or burn
	Inscribed   bool   `json:"inscribed,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Status      string `json:"status"` // mined or pending
	Height      uint32 `json:"height,omitempty"`
	Seen        int64  `json:"seen"` // unix seconds it was recorded
	Seq         int    `json:"seq"`  // its spend sequence, or -1 when there is no resulting location
	MerkleRoot  string `json:"merkle_root,omitempty"`
}

// meta is a chain's summary record.
type meta struct {
	Origin    string `json:"origin"`
	Tip       string `json:"tip"`
	Links     int    `json:"links"`
	Versions  int    `json:"versions"`
	Closed    bool   `json:"closed,omitempty"`
	RemovedAt int64  `json:"removed_at,omitempty"` // unix seconds it left the tracked set
}

// store persists chains in LevelDB:
//
//	m/<origin>        meta
//	l/<origin>/<n>    link n, 0 the origin
//	v/<origin>/<seq>  the index of the link that is version seq
//	o/<outpoint>      the origin and sequence for a version location
type store struct {
	db *leveldb.DB
}

func openStore(path string) (*store, error) {
	db, err := anvilstore.OpenWithRecover(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open version store: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) close() error { return s.db.Close() }

func metaKey(origin string) []byte { return []byte("m/" + origin) }

func linkKey(origin string, n int) []byte { return []byte(fmt.Sprintf("l/%s/%08d", origin, n)) }

func versionKey(origin string, seq int) []byte {
	return []byte(fmt.Sprintf("v/%s/%08d", origin, seq))
}

func outpointKey(outpoint string) []byte { return []byte("o/" + outpoint) }

type locationRef struct {
	Origin string `json:"origin"`
	Seq    int    `json:"seq"`
}

// metas returns every chain's summary.
func (s *store) metas() ([]meta, error) {
	it := s.db.NewIterator(util.BytesPrefix([]byte("m/")), nil)
	defer it.Release()
	var out []meta
	for it.Next() {
		var m meta
		if err := json.Unmarshal(it.Value(), &m); err != nil {
			return nil, fmt.Errorf("decode %s: %w", it.Key(), err)
		}
		out = append(out, m)
	}
	return out, it.Error()
}

func (s *store) meta(origin string) (meta, error) {
	var m meta
	b, err := s.db.Get(metaKey(origin), nil)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func (s *store) link(origin string, n int) (link, error) {
	var l link
	b, err := s.db.Get(linkKey(origin, n), nil)
	if err != nil {
		return l, err
	}
	return l, json.Unmarshal(b, &l)
}

// migrateSequence upgrades inscription-only numbering to spend numbering.
// It is idempotent and can rebuild every v/ key from the persisted links.
func (s *store) migrateSequence(m meta) (meta, error) {
	links := make([]link, m.Links)
	content, contentSeq, seq := m.Origin, 0, 0
	dirty := false
	for i := range links {
		l, err := s.link(m.Origin, i)
		if err != nil {
			return m, err
		}
		wantSeq := -1
		if l.Outpoint != "" {
			wantSeq = seq
			seq++
		}
		if l.Inscribed {
			content, contentSeq = l.Outpoint, wantSeq
		}
		if l.Seq != wantSeq || l.Content != content || l.ContentSeq != contentSeq {
			dirty = true
			l.Seq, l.Content, l.ContentSeq = wantSeq, content, contentSeq
		}
		if wantSeq >= 0 {
			ref, refErr := s.location(l.Outpoint)
			if refErr != nil && refErr != leveldb.ErrNotFound {
				return m, refErr
			}
			if refErr != nil || ref.Origin != m.Origin || ref.Seq != wantSeq {
				dirty = true
			}
		}
		links[i] = l
	}
	if m.Versions != seq {
		dirty = true
		m.Versions = seq
	}
	if !dirty {
		return m, nil
	}
	c := newChange()
	it := s.db.NewIterator(util.BytesPrefix([]byte("v/"+m.Origin+"/")), nil)
	for it.Next() {
		c.b.Delete(append([]byte(nil), it.Key()...))
	}
	err := it.Error()
	it.Release()
	if err != nil {
		return m, err
	}
	for i, l := range links {
		c.putLink(m.Origin, i, l)
	}
	c.putMeta(m)
	return m, s.apply(c)
}

// version returns the link that is origin's version seq.
func (s *store) version(origin string, seq int) (link, error) {
	b, err := s.db.Get(versionKey(origin, seq), nil)
	if err != nil {
		return link{}, err
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return link{}, fmt.Errorf("decode version %d of %s: %w", seq, origin, err)
	}
	return s.link(origin, n)
}

func (s *store) location(outpoint string) (locationRef, error) {
	var ref locationRef
	b, err := s.db.Get(outpointKey(outpoint), nil)
	if err != nil {
		return ref, err
	}
	return ref, json.Unmarshal(b, &ref)
}

// versionOutpoints returns the outpoint of each of origin's versions, in
// order, at most limit of them.
func (s *store) versionOutpoints(origin string, limit int) ([]string, error) {
	it := s.db.NewIterator(util.BytesPrefix([]byte("v/"+origin+"/")), nil)
	defer it.Release()
	var out []string
	for it.Next() && len(out) < limit {
		n, err := strconv.Atoi(string(it.Value()))
		if err != nil {
			return nil, err
		}
		l, err := s.link(origin, n)
		if err != nil {
			return nil, err
		}
		out = append(out, l.Outpoint)
	}
	return out, it.Error()
}

// change is one atomic update to a chain.
type change struct {
	b *leveldb.Batch
}

func newChange() *change { return &change{b: new(leveldb.Batch)} }

func (c *change) putMeta(m meta) {
	b, _ := json.Marshal(m)
	c.b.Put(metaKey(m.Origin), b)
}

func (c *change) putLink(origin string, n int, l link) {
	b, _ := json.Marshal(l)
	c.b.Put(linkKey(origin, n), b)
	if l.Seq >= 0 {
		c.b.Put(versionKey(origin, l.Seq), []byte(strconv.Itoa(n)))
		ref, _ := json.Marshal(locationRef{Origin: origin, Seq: l.Seq})
		c.b.Put(outpointKey(l.Outpoint), ref)
	}
}

func (c *change) deleteLink(origin string, n int, l link) {
	c.b.Delete(linkKey(origin, n))
	if l.Seq >= 0 {
		c.b.Delete(versionKey(origin, l.Seq))
		c.b.Delete(outpointKey(l.Outpoint))
	}
}

func (s *store) apply(c *change) error { return s.db.Write(c.b, nil) }

// drop deletes everything recorded for origin.
func (s *store) drop(origin string) error {
	c := new(leveldb.Batch)
	c.Delete(metaKey(origin))
	m, err := s.meta(origin)
	if err != nil && err != leveldb.ErrNotFound {
		return err
	}
	if err == nil {
		for seq := 0; seq < m.Versions; seq++ {
			l, readErr := s.version(origin, seq)
			if readErr != nil {
				return readErr
			}
			c.Delete(outpointKey(l.Outpoint))
		}
	}
	for _, prefix := range []string{"l/" + origin + "/", "v/" + origin + "/"} {
		it := s.db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
		for it.Next() {
			c.Delete(append([]byte(nil), it.Key()...))
		}
		it.Release()
		if err := it.Error(); err != nil {
			return err
		}
	}
	return s.db.Write(c, nil)
}
