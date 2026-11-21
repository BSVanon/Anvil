//go:build linux || darwin

package sitesfile

import (
	"os"
	"syscall"
)

// flockExclusive and flockUnlock back withLock's cross-process exclusion
// on Anvil's shipped build targets (linux/amd64, linux/arm64; see the
// Makefile's release targets) and on darwin, which also has
// syscall.Flock.
func flockExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func flockUnlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
