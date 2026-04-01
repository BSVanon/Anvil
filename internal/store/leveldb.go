package store

import (
	"log/slog"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// OpenWithRecover opens a LevelDB at path. If the database is corrupted
// (e.g. missing .ldb files after a crash), it attempts automatic recovery
// via RecoverFile before retrying. This prevents crash-loops after
// unclean shutdowns or kernel reboots.
func OpenWithRecover(path string, o *opt.Options) (*leveldb.DB, error) {
	db, err := leveldb.OpenFile(path, o)
	if err == nil {
		return db, nil
	}

	if _, ok := err.(*errors.ErrCorrupted); !ok {
		return nil, err
	}

	slog.Warn("leveldb corrupted, attempting recovery", "path", path, "error", err)

	db, err = leveldb.RecoverFile(path, o)
	if err != nil {
		slog.Error("leveldb recovery failed", "path", path, "error", err)
		return nil, err
	}

	slog.Info("leveldb recovered successfully", "path", path)
	return db, nil
}
