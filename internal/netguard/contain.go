package netguard

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
)

// ErrPanicked is returned, by Contain, for a call that panicked.
var ErrPanicked = errors.New("netguard: recovered a panic")

// Contain runs f and turns a panic in it into an error wrapping ErrPanicked.
// It logs the panic with site, the panic value and the stack, so the code
// that panicked can be found. A nil logger logs to slog.Default().
//
// It is for goroutines Anvil owns that call go-sdk broadcast or lookup code,
// which trusts what peers send: the guard validates what those peers send,
// and Contain keeps a panic it missed from ending the process. It cannot
// recover a panic in a goroutine f starts, such as the one go-sdk's
// resolver and Broadcaster run for each host.
func Contain(logger *slog.Logger, site string, f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if logger == nil {
				logger = slog.Default()
			}
			logger.Error("recovered a panic", "site", site, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			err = fmt.Errorf("%w in %s: %v", ErrPanicked, site, r)
		}
	}()
	return f()
}
