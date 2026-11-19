//go:build race

package scriptguard

// raceEnabled reports a race-detector build, which slows the analysis
// several times over (the worst shapes took up to 521 ms under -race with
// the whole suite running, against 88 ms alone without it), so the
// wall-clock bounds are scaled in one.
const raceEnabled = true
