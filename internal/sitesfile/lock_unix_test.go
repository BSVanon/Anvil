//go:build linux || darwin

package sitesfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWithLock_ExcludesANonCooperatingHolder proves the cross-process
// half of the lock: while WithLock is inside its critical section, a
// second, independent file descriptor on the same lock file — exactly
// what a second OS process opening the same path would have — cannot
// also acquire it, and can once the first holder releases it.
//
// The concurrent-goroutine tests in write_test.go exercise WithLock's
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
		done <- WithLock(path, func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started // WithLock now holds both the mutex and the flock.

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
		t.Fatalf("WithLock: %v", err)
	}

	// Now that the holder released it, the same second descriptor must
	// be able to acquire it.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Errorf("could not acquire the lock after the holder released it: %v", err)
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// TestOpenLockFile_OpensReadOnly proves openLockFile's own choice of
// mode directly: the descriptor it returns must not accept a write.
// That's what lets a process with only read access to the lock file —
// group "anvil", never given write access, the mode a freshly created
// lock file gets — open it at all; an O_RDWR open would fail outright
// on the permission bits, independent of anything flock does.
func TestOpenLockFile_OpensReadOnly(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "sites.conf.lock")

	f, err := openLockFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("openLockFile returned a descriptor that accepted a write; want it opened O_RDONLY")
	}
}

// TestOpenLockFile_ChownsOnlyTheFileItCreates proves the other half of
// openLockFile's contract: it sets an owner on a lock file it creates
// fresh, but never touches one that was already there — the same rule
// write.go's AtomicWriteFile applies to the sites file itself.
func TestOpenLockFile_ChownsOnlyTheFileItCreates(t *testing.T) {
	otherGID, ok := testSecondGID(t)
	if !ok {
		t.Skip("this user belongs to no second group — nothing to prove a gid is left alone with")
	}

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "sites.conf.lock")

	// Pre-create the lock file with a group openLockFile must leave
	// alone, standing in for "root:anvil, set the first time this ran".
	if err := os.WriteFile(lockPath, nil, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(lockPath, -1, otherGID); err != nil {
		t.Fatalf("chown the fixture to the test's own second group: %v", err)
	}

	f, err := openLockFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	_, gid, ok := statOwner(info)
	if !ok {
		t.Skip("no owner information available on this platform")
	}
	if gid != otherGID {
		t.Errorf("gid after opening an already-existing lock file = %d, want the pre-existing %d untouched", gid, otherGID)
	}
}

// TestFlock_ExclusiveLockOnAReadOnlyDescriptorExcludesASecondReadOnlyHolder
// proves the semantics WithLock's doc comment states plainly: on Linux
// and the BSDs, flock(2) places its lock on the open file description
// regardless of the mode (O_RDONLY, O_WRONLY or O_RDWR) it was opened
// with. Two independent O_RDONLY descriptors on the same lock file —
// exactly what openLockFile now opens, and exactly what a daemon with
// only read access to the file will do too — still exclude each other.
func TestFlock_ExclusiveLockOnAReadOnlyDescriptorExcludesASecondReadOnlyHolder(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "sites.conf.lock")

	a, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDONLY, 0640)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := syscall.Flock(int(a.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("a read-only descriptor could not take an exclusive lock: %v", err)
	}

	b, err := os.OpenFile(lockPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := syscall.Flock(int(b.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Error("a second read-only descriptor acquired the lock while the first still held it")
		_ = syscall.Flock(int(b.Fd()), syscall.LOCK_UN)
	}

	_ = syscall.Flock(int(a.Fd()), syscall.LOCK_UN)
	if err := syscall.Flock(int(b.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Errorf("could not acquire the lock after the first holder released it: %v", err)
	}
	_ = syscall.Flock(int(b.Fd()), syscall.LOCK_UN)
}
