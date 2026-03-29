package main

import (
	"strings"
	"testing"
)

func TestIsValidPublicIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// Valid public IPv4
		{"89.144.47.58", true},
		{"212.56.43.191", true},
		{"1.2.3.4", true},
		{"8.8.8.8", true},

		// IPv6 — must reject
		{"2a0f:85c1:b73:5dd::a", false},
		{"::1", false},
		{"fe80::1%eth0", false},

		// Empty / garbage
		{"", false},
		{"not-an-ip", false},
		{"<html>error</html>", false},

		// Loopback — reject
		{"127.0.0.1", false},
		{"127.0.0.2", false},

		// Private ranges — reject
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},

		// Link-local — reject
		{"169.254.1.1", false},

		// Unspecified — reject
		{"0.0.0.0", false},

		// IPv4-mapped IPv6 — contains colon, rejected
		{"::ffff:89.144.47.58", false},
	}
	for _, tt := range tests {
		got := isValidPublicIPv4(tt.input)
		if got != tt.want {
			t.Errorf("isValidPublicIPv4(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestRenderUnitUsesControlGroupStop(t *testing.T) {
	unit := renderUnit("a", "/etc/anvil", "/var/lib/anvil", "/opt/anvil")
	if !strings.Contains(unit, "KillMode=control-group") {
		t.Fatal("expected KillMode=control-group in generated unit")
	}
	if !strings.Contains(unit, "TimeoutStopSec=30") {
		t.Fatal("expected TimeoutStopSec=30 in generated unit")
	}
}
