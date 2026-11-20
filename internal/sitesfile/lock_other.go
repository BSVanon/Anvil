//go:build !linux && !darwin

package sitesfile

import "os"

// flockExclusive and flockUnlock are no-ops here: syscall.Flock does not
// exist outside linux/darwin (e.g. windows), so there is no cross-process
// primitive to call. Anvil's only shipped build targets are linux/amd64
// and linux/arm64 (see the Makefile), where lock_unix.go's real
// implementation applies instead; this fallback exists purely so
// `go build ./...` and `go test ./...` still compile for someone
// developing on a non-unix machine. The in-process mutex in lock.go still
// serialises callers within one process everywhere; only the
// cross-process guarantee is unavailable on a platform that lands here.
func flockExclusive(f *os.File) error { return nil }
func flockUnlock(f *os.File) error    { return nil }
