//go:build race

package beefscan

// raceEnabled reports a race-detector build, which slows go-sdk's parse
// several times over, so the wall-clock bounds are not checked in one.
const raceEnabled = true
