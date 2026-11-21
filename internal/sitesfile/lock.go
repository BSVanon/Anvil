package sitesfile

import (
	"fmt"
	"os"
	"sync"
)

// muRegistry gives every distinct path its own mutex, so two goroutines
// targeting different files never wait on each other.
//
// This in-process mutex and the cross-process flock below guard against
// different things: flock's exclusion is per open-file-description, so
// two goroutines in this same process, each opening its own file
// descriptor on the lock file, would NOT exclude each other through
// flock alone. The mutex is what makes concurrent callers in one process
// safe; the flock is what makes two separate processes safe — the CLI
// and, later, a daemon reading or rewriting the same file. WithLock
// takes both, in that order, for every call.
var (
	muRegistryMu sync.Mutex
	muRegistry   = map[string]*sync.Mutex{}
)

func mutexFor(path string) *sync.Mutex {
	muRegistryMu.Lock()
	defer muRegistryMu.Unlock()
	m, ok := muRegistry[path]
	if !ok {
		m = &sync.Mutex{}
		muRegistry[path] = m
	}
	return m
}

// openLockFile opens lockPath for WithLock, creating it if it doesn't
// exist yet. The open mode is deliberately O_RDONLY, never O_RDWR or
// O_WRONLY: the lock file is never written to (flock needs no write
// access to the file's contents — see WithLock's doc comment for why
// that's safe), and a read-only descriptor is exactly what a process
// with only read access to this file — a daemon running as a member of
// the "anvil" group once something besides the CLI calls into this
// package directly — can still open. Opening O_RDWR would make that
// open fail outright on permission bits alone, long before flock ever
// entered into it.
//
// O_CREATE|O_EXCL is tried first so this call can tell whether it is
// the one bringing lockPath into existence (and so should set its
// owner, below) from finding it already there (whose owner is left
// alone, the same rule write.go's AtomicWriteFile applies to an
// existing sites file).
func openLockFile(lockPath string) (*os.File, error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0640)
	if err == nil {
		uid, gid := newSiteFileOwner()
		if uid >= 0 || gid >= 0 {
			_ = f.Chown(uid, gid) // best effort — see write.go's AtomicWriteFile
		}
		return f, nil
	}
	if !os.IsExist(err) {
		return nil, err
	}
	return os.OpenFile(lockPath, os.O_RDONLY, 0)
}

// WithLock runs fn while holding both the in-process mutex and an
// advisory cross-process lock on path+".lock", for path. Every Add and
// Remove call goes through this, and so does the gateway peers rewrite
// (cmd/anvil), so no two writers to the same file — in this process or
// another — can interleave a read-modify-write.
//
// On Linux and the BSDs, flock(2) places its lock on the open file
// description, not on the file's contents: an exclusive lock excludes
// every other descriptor on the same file regardless of the mode
// (O_RDONLY, O_WRONLY or O_RDWR) any of them were opened with. That's
// what makes openLockFile's O_RDONLY descriptor above still a fully
// effective exclusive lock; lock_unix_test.go proves it directly.
func WithLock(path string, fn func() error) error {
	m := mutexFor(path)
	m.Lock()
	defer m.Unlock()

	f, err := openLockFile(path + ".lock")
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer f.Close()

	if err := flockExclusive(f); err != nil {
		return fmt.Errorf("lock sites file: %w", err)
	}
	defer flockUnlock(f)

	return fn()
}
