//go:build !race

package scriptguard

// raceEnabled reports a race-detector build; see race_on_test.go.
const raceEnabled = false
