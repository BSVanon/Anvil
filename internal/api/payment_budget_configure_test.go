package api

import "testing"

// TestConfigureMintBudgetReplacesDefault: valid burst/perMinute values
// install a budget with exactly that shape — proven by spending the whole
// burst immediately, then confirming the next take is refused.
func TestConfigureMintBudgetReplacesDefault(t *testing.T) {
	prev := defaultMintBudget
	defer func() { defaultMintBudget = prev }()

	ConfigureMintBudget(3, 60) // 3 burst, 60/min so refills aren't reached in-test
	for i := 0; i < 3; i++ {
		if ok, _ := defaultMintBudget.take(); !ok {
			t.Fatalf("take %d: expected burst allowance of 3, got refused", i)
		}
	}
	if ok, _ := defaultMintBudget.take(); ok {
		t.Fatal("expected the 4th immediate take to be refused after a burst of 3")
	}
}

// TestConfigureMintBudgetIgnoresInvalidValues: burst or perMinute below 1
// must be ignored (left at the compiled-in default), not applied — the
// config key is operator-settable TOML, and a 0/negative perMinute would
// divide by zero in newMintBudget if it reached there unguarded.
func TestConfigureMintBudgetIgnoresInvalidValues(t *testing.T) {
	prev := defaultMintBudget
	defer func() { defaultMintBudget = prev }()

	ConfigureMintBudget(5, 10)
	afterValid := defaultMintBudget

	ConfigureMintBudget(0, 10)
	if defaultMintBudget != afterValid {
		t.Fatal("burst < 1 should be ignored, leaving defaultMintBudget unchanged")
	}

	ConfigureMintBudget(5, 0)
	if defaultMintBudget != afterValid {
		t.Fatal("perMinute < 1 should be ignored, leaving defaultMintBudget unchanged")
	}

	ConfigureMintBudget(-1, -1)
	if defaultMintBudget != afterValid {
		t.Fatal("negative burst/perMinute should be ignored, leaving defaultMintBudget unchanged")
	}
}
