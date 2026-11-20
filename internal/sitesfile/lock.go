package sitesfile

import (
	"fmt"
	"os"
	"sync"
)

// muRegistry gives every distinct sites-file path its own mutex, so two
// goroutines targeting different files never wait on each other.
//
// This in-process mutex and the cross-process flock below guard against
// different things: flock's exclusion is per open-file-description, so
// two goroutines in this same process, each opening its own file
// descriptor on the lock file, would NOT exclude each other through
// flock alone. The mutex is what makes concurrent callers in one process
// safe; the flock is what makes a concurrent daemon and CLI, in separate
// processes, safe. withLock takes both, in that order, for every call.
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

// withLock runs fn while holding both the in-process mutex and an
// advisory cross-process lock on path+".lock", for path. Every Add and
// Remove call goes through this, so no two writers to the same sites
// file — in this process or another — can interleave a
// read-modify-write.
func withLock(path string, fn func() error) error {
	m := mutexFor(path)
	m.Lock()
	defer m.Unlock()

	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0640)
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
