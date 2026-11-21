package config

import (
	"strings"
	"testing"
)

func TestLoadContentDefaults(t *testing.T) {
	cfg, err := Load(writeTestConfig(t, t.TempDir(), "[node]\nname = \"test\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Content
	if len(c.TrackOrigins) != 0 || c.MaxTrackedOrigins != 1000 || c.MaxWatchedOutpoints != 10000 ||
		c.SpendPollInterval != 600 || c.TipPendingTimeout != 86400 {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestLoadContentExplicitValues(t *testing.T) {
	upper := strings.Repeat("AB", 32)
	cfg, err := Load(writeTestConfig(t, t.TempDir(), `
[content]
track_origins = ["`+upper+`.2", " `+strings.Repeat("0", 64)+`_0 "]
max_tracked_origins = 5
max_watched_outpoints = 50
spend_poll_interval = 120
tip_pending_timeout = 3600
`))
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Content
	want := []string{strings.ToLower(upper) + "_2", strings.Repeat("0", 64) + "_0"}
	if len(c.TrackOrigins) != 2 || c.TrackOrigins[0] != want[0] || c.TrackOrigins[1] != want[1] {
		t.Fatalf("track_origins = %q, want %q", c.TrackOrigins, want)
	}
	if c.MaxTrackedOrigins != 5 || c.MaxWatchedOutpoints != 50 || c.SpendPollInterval != 120 || c.TipPendingTimeout != 3600 {
		t.Fatalf("values = %+v", c)
	}
}

func TestLoadContentRefusesABadOrigin(t *testing.T) {
	for _, bad := range []string{"", "abc_0", strings.Repeat("0", 64), strings.Repeat("0", 64) + "_x", strings.Repeat("g", 64) + "_0"} {
		_, err := Load(writeTestConfig(t, t.TempDir(), "[content]\ntrack_origins = [\""+bad+"\"]\n"))
		if err == nil || !strings.Contains(err.Error(), "track_origins") {
			t.Fatalf("%q: err %v", bad, err)
		}
	}
}

func TestLoadContentNegativeValuesFailClosed(t *testing.T) {
	for key, body := range map[string]string{
		"max_tracked_origins": "[content]\nmax_tracked_origins = -1\n",
		"spend_poll_interval": "[content]\nspend_poll_interval = -5\n",
	} {
		if _, err := Load(writeTestConfig(t, t.TempDir(), body)); err == nil || !strings.Contains(err.Error(), key) {
			t.Fatalf("%s: error = %v", key, err)
		}
	}
}
