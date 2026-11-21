//go:build linux || darwin

package sitesfile

import (
	"os"
	"syscall"
)

// statOwner extracts the uid and gid an already-Stat'd file is owned by,
// on the platforms (linux and darwin, the same pair lock_unix.go covers)
// where os.FileInfo.Sys() carries a *syscall.Stat_t. ok is false if it
// doesn't — which this build never sees, but AtomicWriteFile's caller
// (owner_other.go, on every other platform) treats the same way.
func statOwner(info os.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
