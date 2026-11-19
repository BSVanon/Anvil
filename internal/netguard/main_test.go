package netguard

import (
	"net/http"
	"os"
	"testing"
)

// capturedBeforeInstall is taken during package initialization, before
// TestMain runs Install, the way a library may hold http.DefaultClient from
// its own initialization. Install must cover it too.
var capturedBeforeInstall = http.DefaultClient

// TestMain installs the guard once, before any test or goroutine uses
// http.DefaultClient, as the node does at start-up. Tests that need an
// unguarded client build their own &http.Client{}, which uses
// http.DefaultTransport directly.
func TestMain(m *testing.M) {
	Install()
	os.Exit(m.Run())
}
