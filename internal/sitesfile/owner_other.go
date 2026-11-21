//go:build !linux && !darwin

package sitesfile

import "os"

// statOwner has nothing to extract outside linux/darwin (see
// lock_other.go for the matching lock fallback, and owner_unix.go for
// the real implementation) — ok is always false, so AtomicWriteFile
// falls back to whatever new-file owner its caller gave it, or leaves
// the file as os.CreateTemp made it if even that is unset. This exists
// purely so `go build ./...` and `go test ./...` keep compiling for
// someone developing on a non-unix machine; see lock_other.go for the
// reasoning.
func statOwner(info os.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
