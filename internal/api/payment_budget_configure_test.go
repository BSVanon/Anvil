package api

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// useMintBudget restores defaultMintBudget when the test ends.
func useMintBudget(t *testing.T) {
	t.Helper()
	prev := defaultMintBudget
	t.Cleanup(func() { defaultMintBudget = prev })
}

// immediateTakes counts how many of n takes, all at one instant, the budget
// grants.
func immediateTakes(b *mintBudget, n int) int {
	granted := 0
	for i := 0; i < n; i++ {
		if ok, _ := b.take(); ok {
			granted++
		}
	}
	return granted
}

// TestConfigureMintBudgetReplacesDefault: valid burst/perMinute values
// install a budget with exactly that shape — proven by spending the whole
// burst immediately, then confirming the next take is refused.
func TestConfigureMintBudgetReplacesDefault(t *testing.T) {
	useMintBudget(t)
	ConfigureMintBudget(3, 60) // 3 burst, 60/min so refills aren't reached in-test
	if got := immediateTakes(defaultMintBudget, 4); got != 3 {
		t.Fatalf("a burst of 3 granted %d of 4 immediate takes", got)
	}
}

// TestConfigureMintBudgetBoundsValues: a value of 0 (unset) or below takes its
// key's default, and a value over its ceiling takes the ceiling, each key on
// its own.
func TestConfigureMintBudgetBoundsValues(t *testing.T) {
	useMintBudget(t)
	cases := []struct {
		burst, perMinute         int
		wantBurst, wantPerMinute int
	}{
		{0, 0, mintBurst, mintsPerMinute},
		{-1, -5, mintBurst, mintsPerMinute},
		{0, 10, mintBurst, 10},
		{5, 0, 5, mintsPerMinute},
		{1 << 40, 2, maxMintBurst, 2},
		{10, 100_000_000_000, 10, maxMintsPerMinute},
		{maxMintBurst, maxMintsPerMinute, maxMintBurst, maxMintsPerMinute},
		{1, 1, 1, 1},
	}
	for _, tc := range cases {
		ConfigureMintBudget(tc.burst, tc.perMinute)
		b := defaultMintBudget
		wantInterval := time.Minute / time.Duration(tc.wantPerMinute)
		if b.interval != wantInterval || b.slack != wantInterval*time.Duration(tc.wantBurst-1) {
			t.Errorf("ConfigureMintBudget(%d, %d): interval=%v slack=%v, want burst %d at %d a minute",
				tc.burst, tc.perMinute, b.interval, b.slack, tc.wantBurst, tc.wantPerMinute)
		}
	}
}

// TestConfigureMintBudgetHugeValuesKeepALimit: a per-minute rate of 1e11
// once made the refill interval zero, granting every mint, and a burst of
// 2^40 gave about 81 years of slack. Bounded, they grant the burst at once
// and nothing more.
func TestConfigureMintBudgetHugeValuesKeepALimit(t *testing.T) {
	useMintBudget(t)
	ConfigureMintBudget(10, 100_000_000_000)
	if got := immediateTakes(defaultMintBudget, 100_000); got != 10 {
		t.Fatalf("x402_mints_per_minute=1e11: %d of 100000 immediate mints granted, want the burst of 10", got)
	}
	ConfigureMintBudget(1<<40, 2)
	if got := immediateTakes(defaultMintBudget, 2*maxMintBurst); got != maxMintBurst {
		t.Fatalf("x402_mint_burst=2^40: %d of %d immediate mints granted, want the ceiling %d", got, 2*maxMintBurst, maxMintBurst)
	}
}

// TestConfigureMintBudgetLogsTheBudgetInEffect: the budget is logged as it
// takes effect, bounded, and a replaced value is warned about.
func TestConfigureMintBudgetLogsTheBudgetInEffect(t *testing.T) {
	useMintBudget(t)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ConfigureMintBudget(-3, 100_000_000_000)
	out := buf.String()
	for _, want := range []string{
		"burst=10 per_minute=60 max_mints_per_hour=3610",
		"setting=x402_mint_burst value=-3 default=10",
		"setting=x402_mints_per_minute value=100000000000 ceiling=60",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}
