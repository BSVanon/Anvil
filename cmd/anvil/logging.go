package main

import (
	"log/slog"

	"github.com/BSVanon/Anvil/internal/overlay/enginelog"
)

// installEngineLog downgrades the overlay engine's own cancelled-read
// Error logging to Debug (see internal/overlay/enginelog) and returns the
// resulting default logger — the same value slog.Default() returns from
// this point on, which is what every constructor below takes as its own
// logger.
func installEngineLog() *slog.Logger {
	return enginelog.Install()
}
