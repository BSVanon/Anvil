package envelope

import (
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func TestEnvelopeIndexMigrationStartIsRecordedOnlyWhenWorkIsNeeded(t *testing.T) {
	path := t.TempDir()
	s, err := NewStore(path, 3600, 65536, func(name string) error {
		t.Fatalf("fresh envelope store recorded migration start %q", name)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	env := validDurableEnvelope(t)
	if err := s.Ingest(env); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	batch := new(leveldb.Batch)
	batch.Delete(durableIndexReady)
	for _, prefix := range [][]byte{prefixExactAll, prefixExactPublic, prefixPublicPull} {
		iter := db.NewIterator(util.BytesPrefix(prefix), nil)
		for iter.Next() {
			batch.Delete(append([]byte(nil), iter.Key()...))
		}
		iter.Release()
	}
	if err := db.Write(batch, nil); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	var migrations []string
	started := func(name string) error {
		migrations = append(migrations, name)
		return nil
	}
	s, err = NewStore(path, 3600, 65536, started)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 1 || migrations[0] != envelopeIndexMigration {
		t.Fatalf("migration starts = %v", migrations)
	}
	if got, err := s.QueryExactTopic(env.Topic, 10); err != nil || len(got) != 1 {
		t.Fatalf("rebuilt index query = %d, %v", len(got), err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewStore(path, 3600, 65536, started)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(migrations) != 1 {
		t.Fatalf("clean reopen recorded migration starts = %v", migrations)
	}
}
