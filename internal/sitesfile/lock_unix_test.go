//go:build linux || darwin

package sitesfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWithLock_ExcludesANonCooperatingHolder proves the cross-process
// half of the lock: while withLock is inside its critical section, a
// second, independent file descriptor on the same lock file — exactly
// what a second OS process opening the same path would have — cannot
// also acquire it, and can once the first holder releases it.
//
// The concurrent-goroutine tests in write_test.go exercise withLock's
// in-process mutex, which alone would pass them even with flock
// stubbed out (two goroutines in one process never contend on the mutex
// and the flock at the same time, since the mutex already serialises
// entry to the flock call). This test is the one that actually exercises
// flock's own exclusion, independent of the mutex.
func TestWithLock_ExcludesANonCooperatingHolder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	lockPath := path + ".lock"

	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withLock(path, func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started // withLock now holds both the mutex and the flock.

	// A second, independent descriptor on the same lock file — standing
	// in for a second process — must not be able to acquire it while the
	// first holder is still inside its critical section.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Error("a second descriptor acquired the lock while the first holder was still inside its critical section")
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("withLock: %v", err)
	}

	// Now that the holder released it, the same second descriptor must
	// be able to acquire it.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Errorf("could not acquire the lock after the holder released it: %v", err)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
